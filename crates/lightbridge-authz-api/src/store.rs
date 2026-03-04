use lightbridge_authz_core::{
    Account, ApiKey, ApiKeySecret, CreateAccount, CreateApiKey, CreateProject, Project,
    RotateApiKey, UpdateAccount, UpdateApiKey, UpdateProject,
};
use lightbridge_authz_core::{async_trait, error::Error};

#[async_trait]
pub trait AuthzStore: Send + Sync + 'static + std::fmt::Debug {
    async fn create_account(&self, subject: &str, input: CreateAccount) -> Result<Account, Error>;
    async fn list_accounts(
        &self,
        subject: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Account>, Error>;
    async fn get_account(&self, subject: &str, account_id: &str) -> Result<Account, Error>;
    async fn update_account(
        &self,
        subject: &str,
        account_id: &str,
        input: UpdateAccount,
    ) -> Result<Account, Error>;
    async fn delete_account(&self, subject: &str, account_id: &str) -> Result<(), Error>;

    async fn create_project(
        &self,
        subject: &str,
        account_id: &str,
        input: CreateProject,
    ) -> Result<Project, Error>;
    async fn list_projects(
        &self,
        subject: &str,
        account_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<Project>, Error>;
    async fn get_project(&self, subject: &str, project_id: &str) -> Result<Project, Error>;
    async fn update_project(
        &self,
        subject: &str,
        project_id: &str,
        input: UpdateProject,
    ) -> Result<Project, Error>;
    async fn delete_project(&self, subject: &str, project_id: &str) -> Result<(), Error>;

    async fn create_api_key(
        &self,
        subject: &str,
        project_id: &str,
        input: CreateApiKey,
    ) -> Result<ApiKeySecret, Error>;
    async fn list_api_keys(
        &self,
        subject: &str,
        project_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<Vec<ApiKey>, Error>;
    async fn get_api_key(&self, subject: &str, key_id: &str) -> Result<ApiKey, Error>;
    async fn update_api_key(
        &self,
        subject: &str,
        key_id: &str,
        input: UpdateApiKey,
    ) -> Result<ApiKey, Error>;
    async fn delete_api_key(&self, subject: &str, key_id: &str) -> Result<(), Error>;
    async fn revoke_api_key(&self, subject: &str, key_id: &str) -> Result<ApiKey, Error>;
    async fn rotate_api_key(
        &self,
        subject: &str,
        key_id: &str,
        input: RotateApiKey,
    ) -> Result<ApiKeySecret, Error>;
}
