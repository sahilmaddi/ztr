pipeline {
    agent any

    stages {
        stage('Validate Regression Services') {
            steps { bat 'python -m py_compile services\\robot\\app.py services\\regression\\app.py' }
        }
        stage('Build Angular') {
            steps { bat 'cd apps\\web && npm ci && npm run build' }
        }
        stage('Build Containers') {
            steps { bat 'docker compose build' }
        }
    }
    post {
        always { junit allowEmptyResults: true, testResults: '**/test-results/*.xml' }
    }
}