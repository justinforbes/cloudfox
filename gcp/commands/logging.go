package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"

	LoggingService "github.com/BishopFox/cloudfox/gcp/services/loggingService"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/BishopFox/cloudfox/internal"
	gcpinternal "github.com/BishopFox/cloudfox/internal/gcp"
	"github.com/spf13/cobra"
)

var GCPLoggingCommand = &cobra.Command{
	Use:     globals.GCP_LOGGING_MODULE_NAME,
	Aliases: []string{"logs", "sinks", "log-sinks"},
	Short:   "Enumerate Cloud Logging sinks and metrics with security analysis",
	Long: `Enumerate Cloud Logging sinks and log-based metrics across projects.

Features:
- Lists all logging sinks (log exports)
- Shows sink destinations (Storage, BigQuery, Pub/Sub, Logging buckets)
- Identifies cross-project log exports
- Shows sink filters and exclusions
- Lists log-based metrics for alerting
- Generates gcloud commands for further analysis

Security Columns:
- Destination: Where logs are exported (bucket, dataset, topic)
- CrossProject: Whether logs are exported to another project
- WriterIdentity: Service account used for export
- Filter: What logs are included/excluded

Attack Surface:
- Cross-project exports may leak logs to external projects
- Sink writer identity may have excessive permissions
- Disabled sinks may indicate log evasion
- Missing sinks may indicate lack of log retention`,
	Run: runGCPLoggingCommand,
}

// ------------------------------
// Module Struct
// ------------------------------
type LoggingModule struct {
	gcpinternal.BaseGCPModule

	ProjectSinks   map[string][]LoggingService.SinkInfo   // projectID -> sinks
	ProjectMetrics map[string][]LoggingService.MetricInfo // projectID -> metrics
	LootMap        map[string]map[string]*internal.LootFile
	mu             sync.Mutex
}

// ------------------------------
// Output Struct
// ------------------------------
type LoggingOutput struct {
	Table []internal.TableFile
	Loot  []internal.LootFile
}

func (o LoggingOutput) TableFiles() []internal.TableFile { return o.Table }
func (o LoggingOutput) LootFiles() []internal.LootFile   { return o.Loot }

// ------------------------------
// Command Entry Point
// ------------------------------
func runGCPLoggingCommand(cmd *cobra.Command, args []string) {
	cmdCtx, err := gcpinternal.InitializeCommandContext(cmd, globals.GCP_LOGGING_MODULE_NAME)
	if err != nil {
		return
	}

	module := &LoggingModule{
		BaseGCPModule:  gcpinternal.NewBaseGCPModule(cmdCtx),
		ProjectSinks:   make(map[string][]LoggingService.SinkInfo),
		ProjectMetrics: make(map[string][]LoggingService.MetricInfo),
		LootMap:        make(map[string]map[string]*internal.LootFile),
	}

	module.Execute(cmdCtx.Ctx, cmdCtx.Logger)
}

// ------------------------------
// Module Execution
// ------------------------------
func (m *LoggingModule) Execute(ctx context.Context, logger internal.Logger) {
	m.RunProjectEnumeration(ctx, logger, m.ProjectIDs, globals.GCP_LOGGING_MODULE_NAME, m.processProject)

	allSinks := m.getAllSinks()
	allMetrics := m.getAllMetrics()

	if len(allSinks) == 0 && len(allMetrics) == 0 {
		logger.InfoM("No logging sinks or metrics found", globals.GCP_LOGGING_MODULE_NAME)
		return
	}

	// Count interesting sinks
	crossProjectCount := 0
	disabledCount := 0
	for _, sink := range allSinks {
		if sink.IsCrossProject {
			crossProjectCount++
		}
		if sink.Disabled {
			disabledCount++
		}
	}

	msg := fmt.Sprintf("Found %d sink(s), %d metric(s)", len(allSinks), len(allMetrics))
	if crossProjectCount > 0 {
		msg += fmt.Sprintf(" [%d cross-project]", crossProjectCount)
	}
	if disabledCount > 0 {
		msg += fmt.Sprintf(" [%d disabled]", disabledCount)
	}
	logger.SuccessM(msg, globals.GCP_LOGGING_MODULE_NAME)

	m.writeOutput(ctx, logger)
}

// getAllSinks returns all sinks from all projects
func (m *LoggingModule) getAllSinks() []LoggingService.SinkInfo {
	var all []LoggingService.SinkInfo
	for _, sinks := range m.ProjectSinks {
		all = append(all, sinks...)
	}
	return all
}

// getAllMetrics returns all metrics from all projects
func (m *LoggingModule) getAllMetrics() []LoggingService.MetricInfo {
	var all []LoggingService.MetricInfo
	for _, metrics := range m.ProjectMetrics {
		all = append(all, metrics...)
	}
	return all
}

// ------------------------------
// Project Processor
// ------------------------------
func (m *LoggingModule) processProject(ctx context.Context, projectID string, logger internal.Logger) {
	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Enumerating Logging in project: %s", projectID), globals.GCP_LOGGING_MODULE_NAME)
	}

	ls := LoggingService.New()

	var projectSinks []LoggingService.SinkInfo
	var projectMetrics []LoggingService.MetricInfo

	// Get sinks
	sinks, err := ls.Sinks(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_LOGGING_MODULE_NAME,
			fmt.Sprintf("Could not enumerate logging sinks in project %s", projectID))
	} else {
		projectSinks = append(projectSinks, sinks...)
	}

	// Get metrics
	metrics, err := ls.Metrics(projectID)
	if err != nil {
		m.CommandCounter.Error++
		gcpinternal.HandleGCPError(err, logger, globals.GCP_LOGGING_MODULE_NAME,
			fmt.Sprintf("Could not enumerate log metrics in project %s", projectID))
	} else {
		projectMetrics = append(projectMetrics, metrics...)
	}

	// Thread-safe store per-project
	m.mu.Lock()
	m.ProjectSinks[projectID] = projectSinks
	m.ProjectMetrics[projectID] = projectMetrics

	// Initialize loot for this project
	if m.LootMap[projectID] == nil {
		m.LootMap[projectID] = make(map[string]*internal.LootFile)
		m.LootMap[projectID]["sinks-commands"] = &internal.LootFile{
			Name:     "sinks-commands",
			Contents: "# Cloud Logging Sinks Commands\n# Generated by CloudFox\n\n",
		}
		m.LootMap[projectID]["sinks-cross-project"] = &internal.LootFile{
			Name:     "sinks-cross-project",
			Contents: "# Cross-Project Log Exports\n# Generated by CloudFox\n# These sinks export logs to external projects\n\n",
		}
		m.LootMap[projectID]["sinks-writer-identities"] = &internal.LootFile{
			Name:     "sinks-writer-identities",
			Contents: "# Logging Sink Writer Identities\n# Generated by CloudFox\n# Service accounts that have write access to destinations\n\n",
		}
		m.LootMap[projectID]["metrics-commands"] = &internal.LootFile{
			Name:     "metrics-commands",
			Contents: "# Cloud Logging Metrics Commands\n# Generated by CloudFox\n\n",
		}
	}

	for _, sink := range projectSinks {
		m.addSinkToLoot(projectID, sink)
	}
	for _, metric := range projectMetrics {
		m.addMetricToLoot(projectID, metric)
	}
	m.mu.Unlock()

	if globals.GCP_VERBOSITY >= globals.GCP_VERBOSE_ERRORS {
		logger.InfoM(fmt.Sprintf("Found %d sink(s), %d metric(s) in project %s", len(projectSinks), len(projectMetrics), projectID), globals.GCP_LOGGING_MODULE_NAME)
	}
}

// ------------------------------
// Loot File Management
// ------------------------------
func (m *LoggingModule) addSinkToLoot(projectID string, sink LoggingService.SinkInfo) {
	lootFile := m.LootMap[projectID]["sinks-commands"]
	if lootFile == nil {
		return
	}

	// Sinks commands file
	lootFile.Contents += fmt.Sprintf(
		"# Sink: %s (Project: %s)\n"+
			"# Destination: %s (%s)\n"+
			"gcloud logging sinks describe %s --project=%s\n",
		sink.Name, sink.ProjectID,
		sink.DestinationType, getDestinationName(sink),
		sink.Name, sink.ProjectID,
	)

	// Add destination-specific commands
	switch sink.DestinationType {
	case "storage":
		if sink.DestinationBucket != "" {
			lootFile.Contents += fmt.Sprintf(
				"gsutil ls gs://%s/\n"+
					"gsutil cat gs://%s/**/*.json 2>/dev/null | head -100\n",
				sink.DestinationBucket, sink.DestinationBucket,
			)
		}
	case "bigquery":
		if sink.DestinationDataset != "" {
			destProject := sink.DestinationProject
			if destProject == "" {
				destProject = sink.ProjectID
			}
			lootFile.Contents += fmt.Sprintf(
				"bq ls %s:%s\n"+
					"bq query --use_legacy_sql=false 'SELECT * FROM `%s.%s.*` LIMIT 100'\n",
				destProject, sink.DestinationDataset,
				destProject, sink.DestinationDataset,
			)
		}
	case "pubsub":
		if sink.DestinationTopic != "" {
			destProject := sink.DestinationProject
			if destProject == "" {
				destProject = sink.ProjectID
			}
			lootFile.Contents += fmt.Sprintf(
				"gcloud pubsub subscriptions create log-capture --topic=%s --project=%s\n"+
					"gcloud pubsub subscriptions pull log-capture --limit=10 --auto-ack --project=%s\n",
				sink.DestinationTopic, destProject, destProject,
			)
		}
	}
	lootFile.Contents += "\n"

	// Cross-project exports
	if sink.IsCrossProject {
		crossProjectLoot := m.LootMap[projectID]["sinks-cross-project"]
		if crossProjectLoot != nil {
			filter := sink.Filter
			if filter == "" {
				filter = "(no filter - all logs)"
			}
			crossProjectLoot.Contents += fmt.Sprintf(
				"# Sink: %s\n"+
					"# Source Project: %s\n"+
					"# Destination Project: %s\n"+
					"# Destination Type: %s\n"+
					"# Destination: %s\n"+
					"# Filter: %s\n"+
					"# Writer Identity: %s\n\n",
				sink.Name,
				sink.ProjectID,
				sink.DestinationProject,
				sink.DestinationType,
				sink.Destination,
				filter,
				sink.WriterIdentity,
			)
		}
	}

	// Writer identities
	if sink.WriterIdentity != "" {
		writerLoot := m.LootMap[projectID]["sinks-writer-identities"]
		if writerLoot != nil {
			writerLoot.Contents += fmt.Sprintf(
				"# Sink: %s -> %s (%s)\n"+
					"%s\n\n",
				sink.Name, sink.DestinationType, getDestinationName(sink),
				sink.WriterIdentity,
			)
		}
	}
}

func (m *LoggingModule) addMetricToLoot(projectID string, metric LoggingService.MetricInfo) {
	lootFile := m.LootMap[projectID]["metrics-commands"]
	if lootFile == nil {
		return
	}
	lootFile.Contents += fmt.Sprintf(
		"# Metric: %s (Project: %s)\n"+
			"gcloud logging metrics describe %s --project=%s\n\n",
		metric.Name, metric.ProjectID,
		metric.Name, metric.ProjectID,
	)
}

// ------------------------------
// Output Generation
// ------------------------------
func (m *LoggingModule) writeOutput(ctx context.Context, logger internal.Logger) {
	if m.Hierarchy != nil && !m.FlatOutput {
		m.writeHierarchicalOutput(ctx, logger)
	} else {
		m.writeFlatOutput(ctx, logger)
	}
}

// getSinksHeader returns the header for sinks table
func (m *LoggingModule) getSinksHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Sink Name",
		"Destination Type",
		"Destination",
		"Cross-Project",
		"Disabled",
		"Writer Identity",
		"Filter",
	}
}

// getMetricsHeader returns the header for metrics table
func (m *LoggingModule) getMetricsHeader() []string {
	return []string{
		"Project Name",
		"Project ID",
		"Metric Name",
		"Description",
		"Filter",
		"Type",
	}
}

// sinksToTableBody converts sinks to table body rows
func (m *LoggingModule) sinksToTableBody(sinks []LoggingService.SinkInfo) [][]string {
	var body [][]string
	for _, sink := range sinks {
		// Format destination
		destination := getDestinationName(sink)

		// Format cross-project
		crossProject := "No"
		if sink.IsCrossProject {
			crossProject = fmt.Sprintf("Yes -> %s", sink.DestinationProject)
		}

		// Format disabled
		disabled := "No"
		if sink.Disabled {
			disabled = "Yes"
		}

		// Format filter (no truncation)
		filter := "-"
		if sink.Filter != "" {
			filter = normalizeFilter(sink.Filter)
		}

		// Format writer identity
		writerIdentity := "-"
		if sink.WriterIdentity != "" {
			writerIdentity = sink.WriterIdentity
		}

		body = append(body, []string{
			m.GetProjectName(sink.ProjectID),
			sink.ProjectID,
			sink.Name,
			sink.DestinationType,
			destination,
			crossProject,
			disabled,
			writerIdentity,
			filter,
		})
	}
	return body
}

// metricsToTableBody converts metrics to table body rows
func (m *LoggingModule) metricsToTableBody(metrics []LoggingService.MetricInfo) [][]string {
	var body [][]string
	for _, metric := range metrics {
		// Format filter (no truncation)
		filter := "-"
		if metric.Filter != "" {
			filter = normalizeFilter(metric.Filter)
		}

		// Format type
		metricType := metric.MetricKind
		if metric.ValueType != "" {
			metricType += "/" + metric.ValueType
		}

		// Format description (no truncation)
		description := metric.Description
		if description == "" {
			description = "-"
		}

		body = append(body, []string{
			m.GetProjectName(metric.ProjectID),
			metric.ProjectID,
			metric.Name,
			description,
			filter,
			metricType,
		})
	}
	return body
}

// buildTablesForProject builds table files for a project
func (m *LoggingModule) buildTablesForProject(projectID string) []internal.TableFile {
	var tableFiles []internal.TableFile

	if sinks, ok := m.ProjectSinks[projectID]; ok && len(sinks) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-sinks",
			Header: m.getSinksHeader(),
			Body:   m.sinksToTableBody(sinks),
		})
	}

	if metrics, ok := m.ProjectMetrics[projectID]; ok && len(metrics) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-metrics",
			Header: m.getMetricsHeader(),
			Body:   m.metricsToTableBody(metrics),
		})
	}

	return tableFiles
}

// writeHierarchicalOutput writes output to per-project directories
func (m *LoggingModule) writeHierarchicalOutput(ctx context.Context, logger internal.Logger) {
	outputData := internal.HierarchicalOutputData{
		OrgLevelData:     make(map[string]internal.CloudfoxOutput),
		ProjectLevelData: make(map[string]internal.CloudfoxOutput),
	}

	for projectID := range m.ProjectSinks {
		tableFiles := m.buildTablesForProject(projectID)

		// Collect loot for this project
		var lootFiles []internal.LootFile
		if projectLoot, ok := m.LootMap[projectID]; ok {
			for _, loot := range projectLoot {
				if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
					lootFiles = append(lootFiles, *loot)
				}
			}
		}

		outputData.ProjectLevelData[projectID] = LoggingOutput{Table: tableFiles, Loot: lootFiles}
	}

	// Also add projects that only have metrics
	for projectID := range m.ProjectMetrics {
		if _, exists := outputData.ProjectLevelData[projectID]; !exists {
			tableFiles := m.buildTablesForProject(projectID)

			var lootFiles []internal.LootFile
			if projectLoot, ok := m.LootMap[projectID]; ok {
				for _, loot := range projectLoot {
					if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
						lootFiles = append(lootFiles, *loot)
					}
				}
			}

			outputData.ProjectLevelData[projectID] = LoggingOutput{Table: tableFiles, Loot: lootFiles}
		}
	}

	pathBuilder := m.BuildPathBuilder()

	err := internal.HandleHierarchicalOutputSmart(
		"gcp",
		m.Format,
		m.Verbosity,
		m.WrapTable,
		pathBuilder,
		outputData,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing hierarchical output: %v", err), globals.GCP_LOGGING_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// writeFlatOutput writes all output to a single directory (legacy mode)
func (m *LoggingModule) writeFlatOutput(ctx context.Context, logger internal.Logger) {
	allSinks := m.getAllSinks()
	allMetrics := m.getAllMetrics()

	// Build table files
	tableFiles := []internal.TableFile{}

	if len(allSinks) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-sinks",
			Header: m.getSinksHeader(),
			Body:   m.sinksToTableBody(allSinks),
		})
	}

	if len(allMetrics) > 0 {
		tableFiles = append(tableFiles, internal.TableFile{
			Name:   globals.GCP_LOGGING_MODULE_NAME + "-metrics",
			Header: m.getMetricsHeader(),
			Body:   m.metricsToTableBody(allMetrics),
		})
	}

	// Collect all loot files
	var lootFiles []internal.LootFile
	for _, projectLoot := range m.LootMap {
		for _, loot := range projectLoot {
			if loot != nil && loot.Contents != "" && !strings.HasSuffix(loot.Contents, "# Generated by CloudFox\n\n") {
				lootFiles = append(lootFiles, *loot)
			}
		}
	}

	output := LoggingOutput{
		Table: tableFiles,
		Loot:  lootFiles,
	}

	scopeNames := make([]string, len(m.ProjectIDs))
	for i, id := range m.ProjectIDs {
		scopeNames[i] = m.GetProjectName(id)
	}

	err := internal.HandleOutputSmart(
		"gcp",
		m.Format,
		m.OutputDirectory,
		m.Verbosity,
		m.WrapTable,
		"project",
		m.ProjectIDs,
		scopeNames,
		m.Account,
		output,
	)
	if err != nil {
		logger.ErrorM(fmt.Sprintf("Error writing output: %v", err), globals.GCP_LOGGING_MODULE_NAME)
		m.CommandCounter.Error++
	}
}

// Helper functions

// getDestinationName returns a human-readable destination name
func getDestinationName(sink LoggingService.SinkInfo) string {
	switch sink.DestinationType {
	case "storage":
		return sink.DestinationBucket
	case "bigquery":
		return sink.DestinationDataset
	case "pubsub":
		return sink.DestinationTopic
	case "logging":
		// Extract bucket name from full path
		parts := strings.Split(sink.Destination, "/")
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
		return sink.Destination
	default:
		return sink.Destination
	}
}

// normalizeFilter normalizes a log filter for display (removes newlines but no truncation)
func normalizeFilter(filter string) string {
	// Remove newlines
	filter = strings.ReplaceAll(filter, "\n", " ")
	filter = strings.ReplaceAll(filter, "\t", " ")

	// Collapse multiple spaces
	for strings.Contains(filter, "  ") {
		filter = strings.ReplaceAll(filter, "  ", " ")
	}

	return strings.TrimSpace(filter)
}
