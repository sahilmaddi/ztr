pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    stages {
        stage('Summarize changelist') {
            steps {
                sh '''
                    echo "Commit: ${GIT_COMMIT:-unknown}"
                    if [ -n "${GIT_PREVIOUS_SUCCESSFUL_COMMIT:-}" ]; then
                        git --no-pager diff --stat "$GIT_PREVIOUS_SUCCESSFUL_COMMIT" "$GIT_COMMIT"
                        git --no-pager diff --name-status "$GIT_PREVIOUS_SUCCESSFUL_COMMIT" "$GIT_COMMIT"
                    else
                        echo "No previous successful build; validating the full checkout."
                        git --no-pager ls-files
                    fi
                '''
            }
        }

        stage('Validate backend syntax') {
            steps {
                sh 'python3 -m py_compile services/robot/app.py services/regression/app.py'
            }
        }

        stage('Build Angular') {
            steps {
                dir('apps/web') {
                    sh 'npm ci && npm run build'
                }
            }
        }

        stage('Build regression containers') {
            steps {
                sh 'docker compose -p ztr build regression browser zap'
            }
        }

        stage('Start regression services') {
            steps {
                sh 'docker compose -p ztr up -d regression browser zap'
            }
        }

        stage('Run browser and ZAP analysis') {
            steps {
                sh '''
                    python3 services/jenkins/package_web.py
                    curl --fail --silent --show-error --retry 30 --retry-connrefused --retry-delay 2 \\
                        http://regression:8100/health
                    curl --fail --silent --show-error --max-time 900 \\
                        -F "file=@ci-web-build.zip" \\
                        http://regression:8100/regress \\
                        --output ci-regression-report.json
                    python3 services/jenkins/check_report.py ci-regression-report.json
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'ci-regression-report.json', allowEmptyArchive: true
        }
    }
}
