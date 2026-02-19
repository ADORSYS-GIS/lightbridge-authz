use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, CreateAccount, CreateApiKey, CreateProject, Project,
    RotateApiKey, UpdateAccount, UpdateApiKey, UpdateProject,
};
use lightbridge_authz_core::{async_trait, error::Error};

#[async_trait]
pub trait AuthzStore: Send + Sync + 'static + std::fmt::Debug {
    async fn create_account(&self, input: CreateAccount) -> Result<Account, Error>;
    async fn list_accounts(&self) -> Result<Vec<Account>, Error>;
    async fn get_account(&self, account_id: &str) -> Result<Account, Error>;
    async fn update_account(
        &self,
        account_id: &str,
        input: UpdateAccount,
    ) -> Result<Account, Error>;
    async fn delete_account(&self, account_id: &str) -> Result<(), Error>;

    async fn create_project(
        &self,
        account_id: &str,
        input: CreateProject,
    ) -> Result<Project, Error>;
    async fn list_projects(&self, account_id: &str) -> Result<Vec<Project>, Error>;
    async fn get_project(&self, project_id: &str) -> Result<Project, Error>;
    async fn update_project(
        &self,
        project_id: &str,
        input: UpdateProject,
    ) -> Result<Project, Error>;
    async fn delete_project(&self, project_id: &str) -> Result<(), Error>;

    async fn create_api_key(
        &self,
        project_id: &str,
        input: CreateApiKey,
    ) -> Result<ApiKeySecret, Error>;
    async fn list_api_keys(&self, project_id: &str) -> Result<Vec<ApiKey>, Error>;
    async fn get_api_key(&self, key_id: &str) -> Result<ApiKey, Error>;
    async fn update_api_key(&self, key_id: &str, input: UpdateApiKey) -> Result<ApiKey, Error>;
    async fn delete_api_key(&self, key_id: &str) -> Result<(), Error>;
    async fn revoke_api_key(&self, key_id: &str) -> Result<ApiKey, Error>;
    async fn rotate_api_key(
        &self,
        key_id: &str,
        input: RotateApiKey,
    ) -> Result<ApiKeySecret, Error>;
}
