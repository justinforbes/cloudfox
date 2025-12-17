package globals

// Module names
const GCP_ARTIFACT_RESGISTRY_MODULE_NAME string = "artifact-registry"
const GCP_BIGQUERY_MODULE_NAME string = "bigquery"
const GCP_BUCKETS_MODULE_NAME string = "buckets"
const GCP_INSTANCES_MODULE_NAME string = "instances"
const GCP_IAM_MODULE_NAME string = "iam"
const GCP_PERMISSIONS_MODULE_NAME string = "permissions"
const GCP_SECRETS_MODULE_NAME string = "secrets"
const GCP_WHOAMI_MODULE_NAME string = "whoami"

// New module names for future implementation
const GCP_FUNCTIONS_MODULE_NAME string = "functions"
const GCP_CLOUDRUN_MODULE_NAME string = "cloudrun"
const GCP_CLOUDSQL_MODULE_NAME string = "cloudsql"
const GCP_GKE_MODULE_NAME string = "gke"
const GCP_PUBSUB_MODULE_NAME string = "pubsub"
const GCP_KMS_MODULE_NAME string = "kms"
const GCP_SERVICEACCOUNTS_MODULE_NAME string = "serviceaccounts"
const GCP_LOGGING_MODULE_NAME string = "logging"
const GCP_NETWORKS_MODULE_NAME string = "networks"
const GCP_FIREWALL_MODULE_NAME string = "firewall"

// Verbosity levels (matching Azure pattern)
var GCP_VERBOSITY int = 0

const GCP_VERBOSE_ERRORS = 9

// const GCP_INVENTORY_MODULE_NAME string = "inventory"
// const GCP_GCLOUD_REFRESH_TOKENS_DB_PATH = ".config/gcloud/credentials.db"
// const GCP_GCLOUD_ACCESS_TOKENS_DB_PATH = ".config/gcloud/access_tokens.db"
// const GCP_GCLOUD_DEFAULT_CONFIG_PATH = ".config/gcloud/configurations/config_default"
// const GCP_GCLOUD_APPLICATION_DEFAULT_PATH = ".config/gcloud/application_default_credentials.json"
