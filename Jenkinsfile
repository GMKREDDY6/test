pipeline {
  environment {
    registry = "bds1959/petclinic"
    registryCredential = 'git-docker'
    dockerImage = ''
  }
  agent {
        label "master"
    }
    tools {
        // Note: this should match with the tool name configured in your jenkins instance (JENKINS_URL/configureTools/)
        maven "MAVEN_HOME"
    }
  stages {
    stage('Cloning Git') {
            steps {
                    git credentialsId: 'git-docker', url: 'https://github.com/bds1959/spring-petclinic.git'
                }
    }
    stage("mvn build") {
            steps {
                script {
                    // Since unit testing is out of the scope we skip them
                    sh "mvn package -DskipTests=true"
                }
            }
    }
    stage('Building image') {
            steps{
                script {
                    dockerImage = docker.build registry + ":$BUILD_NUMBER"
                }
            }
    }
    stage('Deploy Image') {
            steps{
                script {
                    docker.withRegistry( '', registryCredential ) {
                    dockerImage.push()
                    }
                }
            }
    }
    stage('Remove Unused docker image') {
            steps{
                script {
                    sh "docker rmi $registry:$BUILD_NUMBER"
                }
            }
    }
    stage('Deploying cookbook on Node'){
            steps{
                script {
                    sshPublisher(publishers: [sshPublisherDesc(configName: ', transfers: [sshTransfer(cleanRemote: false, excludes: '', execCommand: 'cd chef-repo/cookbooks; knife cookbook upload petclinic', execTimeout: 120000, flatten: false, makeEmptyDirs: false, noDefaultExcludes: false, patternSeparator: '[, ]+', remoteDirectory: '', remoteDirectorySDF: false, removePrefix: '', sourceFiles: '')], usePromotionTimestamp: false, useWorkspaceInPromotion: false, verbose: false)]) 
                }
            }
    }        
  }
}
