use crate::rules::CompiledRule;

#[derive(Debug)]
pub struct RuleMatch {
    pub name: String,
    pub count: usize,
}

#[derive(Debug)]
pub struct SanitizeResult {
    pub text: String,
    pub total_redactions: usize,
    pub matches: Vec<RuleMatch>,
}

pub fn sanitize(text: &str, rules: &[CompiledRule]) -> SanitizeResult {
    let mut output = text.to_string();
    let mut matches = Vec::new();
    let mut total = 0;

    for rule in rules {
        let label = format!("[REDACTED:{}]", rule.name);
        let mut count = 0;

        if rule.has_named_group {
            let mut new_output = String::with_capacity(output.len());
            let mut last_end = 0;

            for caps in rule.regex.captures_iter(&output) {
                if let Some(m) = caps.name("m") {
                    new_output.push_str(&output[last_end..m.start()]);
                    new_output.push_str(&label);
                    last_end = m.end();
                    count += 1;
                }
            }
            new_output.push_str(&output[last_end..]);
            output = new_output;
        } else {
            output = rule
                .regex
                .replace_all(&output, |_: &regex::Captures| {
                    count += 1;
                    label.as_str()
                })
                .into_owned();
        }

        if count > 0 {
            total += count;
            matches.push(RuleMatch {
                name: rule.name.clone(),
                count,
            });
        }
    }

    SanitizeResult {
        text: output,
        total_redactions: total,
        matches,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{compile_rules, default_rules};

    fn compiled_defaults() -> Vec<CompiledRule> {
        compile_rules(&default_rules()).unwrap()
    }

    #[test]
    fn test_aws_access_key() {
        let rules = compiled_defaults();
        let input = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
        let result = sanitize(input, &rules);
        assert!(result.total_redactions >= 1);
        assert!(result.text.contains("[REDACTED:AWS_ACCESS_KEY]"));
        assert!(!result.text.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_github_token() {
        let rules = compiled_defaults();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let result = sanitize(input, &rules);
        assert!(result.total_redactions >= 1);
        assert!(result.text.contains("[REDACTED:GITHUB_TOKEN]"));
    }

    #[test]
    fn test_private_key() {
        let rules = compiled_defaults();
        let input =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/yGaF\n-----END RSA PRIVATE KEY-----";
        let result = sanitize(input, &rules);
        assert!(result.total_redactions >= 1);
        assert!(result.text.contains("[REDACTED:PRIVATE_KEY]"));
    }

    #[test]
    fn test_connection_string() {
        let rules = compiled_defaults();
        let input = "DATABASE_URL=postgresql://admin:supersecret@db.example.com:5432/mydb";
        let result = sanitize(input, &rules);
        assert!(result.total_redactions >= 1);
        assert!(result.text.contains("[REDACTED:CONNECTION_STRING]"));
    }

    #[test]
    fn test_no_redactions() {
        let rules = compiled_defaults();
        let input = "Hello, this is just a normal string with no secrets.";
        let result = sanitize(input, &rules);
        assert_eq!(result.total_redactions, 0);
        assert_eq!(result.text, input);
    }

    #[test]
    fn test_disabled_rule() {
        let mut rules = default_rules();
        for rule in &mut rules {
            rule.enabled = false;
        }
        let compiled = compile_rules(&rules).unwrap();
        let input = "AKIAIOSFODNN7EXAMPLE";
        let result = sanitize(input, &compiled);
        assert_eq!(result.total_redactions, 0);
    }

    #[test]
    fn test_stripe_key() {
        let rules = compiled_defaults();
        // Build the test key at runtime to avoid GitHub push protection false positives
        let fake_key = format!("{}_{}", "sk_live", "00000000000000FAKEFAKE0000");
        let input = format!("STRIPE_KEY={}", fake_key);
        let result = sanitize(&input, &rules);
        assert!(result.total_redactions >= 1);
        assert!(result.text.contains("[REDACTED:STRIPE_SECRET_KEY]"));
    }

    #[test]
    fn test_env_password() {
        let rules = compiled_defaults();
        let input = "PASSWORD=hunter2\nSECRET=mysecretvalue\nAPI_KEY=abcdef123456";
        let result = sanitize(input, &rules);
        assert!(result.total_redactions >= 3);
    }

    #[test]
    fn test_google_api_key() {
        let rules = compiled_defaults();
        let input = "key=AIzaSyA1234567890abcdefghijklmnopqrstuvw";
        let result = sanitize(input, &rules);
        assert!(result.total_redactions >= 1);
        assert!(result.text.contains("[REDACTED:GOOGLE_API_KEY]"));
    }

    #[test]
    fn test_docker_compose_passwords() {
        let rules = compiled_defaults();
        let input = "POSTGRES_PASSWORD=mypassword\nMYSQL_ROOT_PASSWORD=rootpw\nMONGO_INITDB_ROOT_PASSWORD=mongopw";
        let result = sanitize(input, &rules);
        assert!(result.total_redactions >= 3);
    }

    #[test]
    fn test_multiple_secrets_in_one_text() {
        let rules = compiled_defaults();
        let input = r#"
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgresql://admin:secret@localhost:5432/db
PASSWORD=hunter2
"#;
        let result = sanitize(input, &rules);
        assert!(result.total_redactions >= 4);
        assert!(!result.text.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!result
            .text
            .contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
    }

    #[test]
    fn test_github_pat() {
        let rules = compiled_defaults();
        let input = "token=github_pat_ABCDEFGHIJKLMNOPQRSTUV";
        let result = sanitize(input, &rules);
        assert!(result.total_redactions >= 1);
        assert!(result.text.contains("[REDACTED:GITHUB_PAT]"));
    }

    #[test]
    fn test_mongodb_connection_string() {
        let rules = compiled_defaults();
        let input = "MONGO_URI=mongodb+srv://user:pass123@cluster0.abc.mongodb.net/mydb";
        let result = sanitize(input, &rules);
        assert!(result.text.contains("[REDACTED:CONNECTION_STRING]"));
    }

    #[test]
    fn test_no_false_positive_on_normal_urls() {
        let rules = compiled_defaults();
        let input = "Visit https://example.com/page?query=hello for details";
        let result = sanitize(input, &rules);
        assert_eq!(result.total_redactions, 0);
        assert_eq!(result.text, input);
    }
}
