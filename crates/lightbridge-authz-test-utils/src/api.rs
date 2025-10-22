/// A utility client for making HTTP requests to the test server.
pub struct TestClient {
    client: reqwest::Client,
    base_url: String,
}

impl TestClient {
    /// Creates a new `TestClient` instance.
    pub fn new(base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
        }
    }

    /// Sends a GET request to the test server.
    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("{}/{}", self.base_url, path))
            .send()
            .await
            .expect("Failed to send GET request")
    }

    /// Sends a POST request to the test server.
    pub async fn post<T: serde::Serialize>(&self, path: &str, body: T) -> reqwest::Response {
        self.client
            .post(format!("{}/{}", self.base_url, path))
            .json(&body)
            .send()
            .await
            .expect("Failed to send POST request")
    }

    /// Sends a PATCH request to the test server.
    pub async fn patch<T: serde::Serialize>(&self, path: &str, body: T) -> reqwest::Response {
        self.client
            .patch(format!("{}/{}", self.base_url, path))
            .json(&body)
            .send()
            .await
            .expect("Failed to send PATCH request")
    }

    /// Sends a DELETE request to the test server.
    pub async fn delete(&self, path: &str) -> reqwest::Response {
        self.client
            .delete(format!("{}/{}", self.base_url, path))
            .send()
            .await
            .expect("Failed to send DELETE request")
    }
}
