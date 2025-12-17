package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	artifactregistry "cloud.google.com/go/artifactregistry/apiv1"
	ArtifactRegistryService "github.com/BishopFox/cloudfox/gcp/services/artifactRegistryService"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	"github.com/spf13/cobra"
)

var GCPArtifactRegistryCommand = &cobra.Command{
	Use:     globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME,
	Aliases: []string{"ar", "artifacts", "gcr"},
	Short:   "Enumerate GCP Artifact Registry and Container Registry with security configuration",
	Long: `Enumerate GCP Artifact Registry and legacy Container Registry (gcr.io) with security-relevant details.

Features:
- Lists all Artifact Registry repositories with security configuration
- Shows Docker images and package artifacts with tags and digests
- Enumerates IAM policies per repository and identifies public repositories
- Shows encryption type (Google-managed vs CMEK)
- Shows repository mode (standard, virtual, remote)
- Generates gcloud commands for artifact enumeration
- Generates exploitation commands for artifact access
- Enumerates legacy Container Registry (gcr.io) locations

Security Columns:
- Public: Whether the repository has allUsers or allAuthenticatedUsers access
- Encryption: "Google-managed" or "CMEK" (customer-managed keys)
- Mode: STANDARD_REPOSITORY, VIRTUAL_REPOSITORY, or REMOTE_REPOSITORY
- RegistryType: "artifact-registry" or "container-registry" (legacy gcr.io)`,
	Run: runGCPArtifactRegistryCommand,
}

// ------------------------------
// Module Struct with embedded BaseGCPModule
// ------------------------------
type ArtifactRegistryModule struct {
	gcpinternal.BaseGCPModule

	// Module-specific fields
	Artifacts    []ArtifactRegistryService.ArtifactInfo
	Repositories []ArtifactRegistryService.RepositoryInfo
	LootMap      map[string]*internal.LootFile
	client       *artifactregistry.Client
	mu           sync.Mutex
}

// ------------------------------
// Output Struct implementing CloudfoxOutput interface
// ------------------------------
type ArtifactRegistryOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o ArtifactRegistryOutput) TableFiles() []internal.TableFile { return o.Table }
func (o ArtifactRegistryOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPArtifactRegistryCommand(cmd *cobra.Command, args []string) {
	// Initialize command context
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	if err != nil {
		return // Error already logged
	}

	// Create Artifact Registry client
	client, err := artifactregistry.NewClient(cmdCtx.Ctx)
	if err != nil {
		cmdCtx.Logger.ErrorM(fmt.Sprintf("Failed to create Artifact Registry client: %v", err), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		return
	}
	defer client.Close()

	// Create module instance
	module := &ArtifactRegistryModule{
		BaseGCPModule: gcpinternal.NewBaseGCPModule(cmdCtx),
		Artifacts:     []ArtifactRegistryService.ArtifactInfo{},
		Repositories:  []ArtifactRegistryService.RepositoryInfo{},
		LootMap:       make(map[string]*internal.LootFile),
		client:        client,
	}

	// Initialize loot files
	module.initializeLootFiles()

	// Execute enumeration
	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *ArtifactRegistryModule) Execute(ctx context.Context, logger internal.Logger) {
	// Run enumeration with concurrency
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME, m.processProject)

	// Check results
	if len(m.Repositories) == 0 && len(m.Artifacts) == 0 {
		logger.InfoM("No artifact registries found", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		return
	}

	logger.SuccessM(fmt.Sprintf("Found %d repository(ies) with %d artifact(s)", len(m.Repositories), len(m.Artifacts)), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)

	// Write output
	m.writeOutput(ctx, logger)
}

// ------------------------------
// Project Processor (called concurrently for each project)
// ------------------------------
func (m *ArtifactRegistryModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating artifact registries in project: %s", projectID), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}

	// Create service and fetch data
	ars := ArtifactRegistryService.New(m.client)
	result, err := ars.RepositoriesAndArtifacts(projectID)
	if err != nil {
		m.CommandCounter.Error++
		if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
			logger.ErrorM(fmt.Sprintf("Error enumerating artifact registries in project %s: %v", projectID, err), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		}
		return
	}

	// Thread-safe append
	m.mu.Lock()
	m.Repositories = append(m.Repositories, result.Repositories...)
	m.Artifacts = append(m.Artifacts, result.Artifacts...)

	// Generate loot for each repository and artifact
	for _, repo := range result.Repositories {
		m.addRepositoryToLoot(repo)
	}
	for _, artifact := range result.Artifacts {
		m.addArtifactToLoot(artifact)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d repository(ies) and %d artifact(s) in project %s", len(result.Repositories), len(result.Artifacts), projectID), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *ArtifactRegistryModule) initializeLootFiles() {
	m.LootMap["artifact-registry-gcloud-commands"] = &internal.LootFile{
		Name:     "artifact-registry-gcloud-commands",
		Contents: "# GCP Artifact Registry Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["artifact-registry-docker-commands"] = &internal.LootFile{
		Name:     "artifact-registry-docker-commands",
		Contents: "# GCP Artifact Registry Docker Commands\n# Generated by CloudFox\n\n",
	}
	m.LootMap["artifact-registry-exploitation"] = &internal.LootFile{
		Name:     "artifact-registry-exploitation",
		Contents: "# GCP Artifact Registry Exploitation Commands\n# Generated by CloudFox\n# WARNING: Only use with proper authorization\n\n",
	}
	m.LootMap["artifact-registry-public"] = &internal.LootFile{
		Name:     "artifact-registry-public",
		Contents: "# PUBLIC GCP Artifact Registry Repositories\n# Generated by CloudFox\n# These repositories have allUsers or allAuthenticatedUsers access!\n\n",
	}
	m.LootMap["artifact-registry-iam-bindings"] = &internal.LootFile{
		Name:     "artifact-registry-iam-bindings",
		Contents: "# GCP Artifact Registry IAM Bindings\n# Generated by CloudFox\n\n",
	}
	m.LootMap["container-registry-commands"] = &internal.LootFile{
		Name:     "container-registry-commands",
		Contents: "# GCP Container Registry (gcr.io) Commands\n# Generated by CloudFox\n# Legacy Container Registry - consider migrating to Artifact Registry\n\n",
	}
}

func (m *ArtifactRegistryModule) addRepositoryToLoot(repo ArtifactRegistryService.RepositoryInfo) {
	// Extract repo name from full path
	repoName := repo.Name
	parts := strings.Split(repo.Name, "/")
	if len(parts) > 0 {
		repoName = parts[len(parts)-1]
	}

	// Handle legacy Container Registry differently
	if repo.RegistryType == "container-registry" {
		m.LootMap["container-registry-commands"].Contents += fmt.Sprintf(
			"# Container Registry: %s (Project: %s)\n"+
				"# Configure Docker authentication:\n"+
				"gcloud auth configure-docker %s\n"+
				"# List images:\n"+
				"gcloud container images list --repository=%s/%s\n"+
				"# Check for public access (via storage bucket):\n"+
				"gsutil iam get gs://artifacts.%s.appspot.com\n\n",
			repo.Name, repo.ProjectID,
			strings.Split(repo.Name, "/")[0], // gcr.io hostname
			strings.Split(repo.Name, "/")[0], repo.ProjectID,
			repo.ProjectID,
		)
		return
	}

	// gcloud commands for Artifact Registry enumeration
	m.LootMap["artifact-registry-gcloud-commands"].Contents += fmt.Sprintf(
		"# Repository: %s (Project: %s, Location: %s, Format: %s)\n"+
			"# Mode: %s, Encryption: %s, Public: %s\n"+
			"gcloud artifacts repositories describe %s --project=%s --location=%s\n"+
			"gcloud artifacts repositories get-iam-policy %s --project=%s --location=%s\n\n",
		repoName, repo.ProjectID, repo.Location, repo.Format,
		repo.Mode, repo.EncryptionType, repo.PublicAccess,
		repoName, repo.ProjectID, repo.Location,
		repoName, repo.ProjectID, repo.Location,
	)

	// Docker commands for Docker repositories
	if repo.Format == "DOCKER" {
		m.LootMap["artifact-registry-docker-commands"].Contents += fmt.Sprintf(
			"# Docker Repository: %s\n"+
				"# Configure Docker authentication:\n"+
				"gcloud auth configure-docker %s-docker.pkg.dev\n"+
				"# List images:\n"+
				"gcloud artifacts docker images list %s-docker.pkg.dev/%s/%s\n\n",
			repoName,
			repo.Location,
			repo.Location, repo.ProjectID, repoName,
		)
	}

	// Public repositories
	if repo.IsPublic {
		m.LootMap["artifact-registry-public"].Contents += fmt.Sprintf(
			"# REPOSITORY: %s\n"+
				"# Project: %s, Location: %s\n"+
				"# Public Access: %s\n"+
				"# Format: %s, Mode: %s\n"+
				"gcloud artifacts repositories get-iam-policy %s --project=%s --location=%s\n\n",
			repoName,
			repo.ProjectID, repo.Location,
			repo.PublicAccess,
			repo.Format, repo.Mode,
			repoName, repo.ProjectID, repo.Location,
		)
	}

	// IAM bindings
	if len(repo.IAMBindings) > 0 {
		m.LootMap["artifact-registry-iam-bindings"].Contents += fmt.Sprintf(
			"# Repository: %s (Project: %s, Location: %s)\n",
			repoName, repo.ProjectID, repo.Location,
		)
		for _, binding := range repo.IAMBindings {
			m.LootMap["artifact-registry-iam-bindings"].Contents += fmt.Sprintf(
				"# Role: %s\n#   Members: %s\n",
				binding.Role,
				strings.Join(binding.Members, ", "),
			)
		}
		m.LootMap["artifact-registry-iam-bindings"].Contents += "\n"
	}
}

func (m *ArtifactRegistryModule) addArtifactToLoot(artifact ArtifactRegistryService.ArtifactInfo) {
	// Exploitation commands for Docker images
	if artifact.Format == "DOCKER" {
		m.LootMap["artifact-registry-exploitation"].Contents += fmt.Sprintf(
			"# Docker Image: %s (Version: %s)\n"+
				"# Pull image:\n"+
				"docker pull %s-docker.pkg.dev/%s/%s/%s:%s\n"+
				"# Inspect image:\n"+
				"docker inspect %s-docker.pkg.dev/%s/%s/%s:%s\n"+
				"# Run image for analysis:\n"+
				"docker run -it --entrypoint /bin/sh %s-docker.pkg.dev/%s/%s/%s:%s\n\n",
			artifact.Name, artifact.Version,
			artifact.Location, artifact.ProjectID, artifact.Repository, artifact.Name, artifact.Version,
			artifact.Location, artifact.ProjectID, artifact.Repository, artifact.Name, artifact.Version,
			artifact.Location, artifact.ProjectID, artifact.Repository, artifact.Name, artifact.Version,
		)
	}
}

// ------------------------------
// Helper Functions
// ------------------------------
func artifactBoolToCheck(b bool) string {
	if b {
		return "✓"
	}
	return "-"
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *ArtifactRegistryModule) writeOutput(ctx context.Context, logger internal.Logger) {
	// Main repository table with security-relevant columns
	repoHeader := []string{
		"Project ID",
		"Name",
		"Format",
		"Location",
		"Mode",
		"Public",
		"Encryption",
		"RegistryType",
		"Size",
	}

	var repoBody [][]string
	for _, repo := range m.Repositories {
		// Extract repo name from full path
		repoName := repo.Name
		parts := strings.Split(repo.Name, "/")
		if len(parts) > 0 {
			repoName = parts[len(parts)-1]
		}

		// Format public access display
		publicDisplay := repo.PublicAccess
		if repo.IsPublic {
			publicDisplay = "PUBLIC: " + repo.PublicAccess
		}

		// Shorten mode for display
		mode := repo.Mode
		mode = strings.TrimPrefix(mode, "REPOSITORY_MODE_")
		mode = strings.TrimSuffix(mode, "_REPOSITORY")

		repoBody = append(repoBody, []string{
			repo.ProjectID,
			repoName,
			repo.Format,
			repo.Location,
			mode,
			publicDisplay,
			repo.EncryptionType,
			repo.RegistryType,
			repo.SizeBytes,
		})
	}

	// Artifact table with enhanced fields
	artifactHeader := []string{
		"Project ID",
		"Name",
		"Repository",
		"Location",
		"Tags",
		"Digest",
		"Size",
		"Uploaded",
	}

	var artifactBody [][]string
	for _, artifact := range m.Artifacts {
		// Format tags
		tags := "-"
		if len(artifact.Tags) > 0 {
			if len(artifact.Tags) <= 3 {
				tags = strings.Join(artifact.Tags, ", ")
			} else {
				tags = fmt.Sprintf("%s (+%d more)", strings.Join(artifact.Tags[:3], ", "), len(artifact.Tags)-3)
			}
		}

		// Shorten digest for display
		digest := artifact.Digest
		if len(digest) > 16 {
			digest = digest[:16] + "..."
		}

		artifactBody = append(artifactBody, []string{
			artifact.ProjectID,
			artifact.Name,
			artifact.Repository,
			artifact.Location,
			tags,
			digest,
			artifact.SizeBytes,
			artifact.Uploaded,
		})
	}

	// IAM bindings table - one row per member
	iamHeader := []string{
		"Repository",
		"Project ID",
		"Location",
		"Role",
		"Member Type",
		"Member",
	}

	var iamBody [][]string
	for _, repo := range m.Repositories {
		// Skip container-registry entries (no IAM at repo level)
		if repo.RegistryType == "container-registry" {
			continue
		}

		repoName := repo.Name
		parts := strings.Split(repo.Name, "/")
		if len(parts) > 0 {
			repoName = parts[len(parts)-1]
		}

		for _, binding := range repo.IAMBindings {
			for _, member := range binding.Members {
				memberType := ArtifactRegistryService.GetMemberType(member)
				iamBody = append(iamBody, []string{
					repoName,
					repo.ProjectID,
					repo.Location,
					binding.Role,
					memberType,
					member,
				})
			}
		}
	}

	// Public repositories table
	publicHeader := []string{
		"Repository",
		"Project ID",
		"Location",
		"Format",
		"Public Access",
		"Mode",
	}

	var publicBody [][]string
	for _, repo := range m.Repositories {
		if repo.IsPublic {
			repoName := repo.Name
			parts := strings.Split(repo.Name, "/")
			if len(parts) > 0 {
				repoName = parts[len(parts)-1]
			}

			publicBody = append(publicBody, []string{
				repoName,
				repo.ProjectID,
				repo.Location,
				repo.Format,
				repo.PublicAccess,
				repo.Mode,
			})
		}
	}

	// Collect loot files
	var lootFiles []internal.LootFile
	for _, loot := range m.LootMap {
		if loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
			lootFiles = append(lootFiles, *loot)
		}
	}

	// Build table files
	tableFiles := []internal.TableFile{
		{
			Name:   fmt.Sprintf("%s-repos", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME),
			Header: repoHeader,
			Body:   repoBody,
		},
	}

	// Add artifacts table if there are any
	if len(artifactBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   fmt.Sprintf("%s-artifacts", globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME),
			Header: artifactHeader,
			Body:   artifactBody,
		})
	}

	// Add IAM table if there are bindings
	if len(iamBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "artifact-registry-iam",
			Header: iamHeader,
			Body:   iamBody,
		})
	}

	// Add public repositories table if any
	if len(publicBody) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   "artifact-registry-public",
			Header: publicHeader,
			Body:   publicBody,
		})
	}

	output := ArtifactRegistryOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	// Write output using HandleOutputSmart with scope support
	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",           // scopeType
		m.ProjectIDs,        // scopeIdentifiers
		m.ProjectIDs,        // scopeNames (same as IDs for GCP projects)
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_ARTIFACT_RESGISTRY_MODULE_NAME)
		m.CommandCounter.Error++
	}
}
