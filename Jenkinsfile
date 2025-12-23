pipeline {
    agent any

    environment {
        PYTHON = "python3"
        VENV   = ".venv"
        LOCAL_TTL  = "${env.LOCAL_TTL ?: 'local_ontology.ttl'}"
        GLOBAL_TTL = "${env.GLOBAL_TTL ?: 'augmented_ontology.ttl'}"
    }

    stages {

        stage('Setup Python') {
            steps {
                sh """
                ${PYTHON} -m venv ${VENV}
                . ${VENV}/bin/activate
                pip install --upgrade pip
                pip install -r requirements.txt
                """
            }
        }

        stage('Run vulnerability_scanner.py') {
            steps {
                sh """
                . ${VENV}/bin/activate
                ${PYTHON} vulnerability_scanner.py
                """
            }
        }

        stage('Check vulnerability_scanner.py Output') {
            steps {
                sh "test -f ${LOCAL_TTL}"
            }
        }

        stage('Merge TTL Files') {
            steps {
                sh """
                . ${VENV}/bin/activate
                ${PYTHON} ontology_merger.py
                """
            }
        }

        stage('Run global_augmenter.py') {
            steps {
                sh """
                . ${VENV}/bin/activate
                ${PYTHON} global_augmenter.py \
                  --input global_ontology.ttl \
                  --atlas ATLAS.yaml \
                  --base-onto base_ontology.ttl \
                  --output ${GLOBAL_TTL}
                """
            }
        }

        stage('Save Results') {
            steps {
                archiveArtifacts artifacts: "*.ttl"
            }
        }
    }
}

