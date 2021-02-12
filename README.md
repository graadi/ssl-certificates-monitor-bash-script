# SSL Certificates Monitor Bash Script

The monitoring tool is a Jenkins job, based on a custom written declarative pipeline that invokes an Bash script, along with further configuration to check a predefined set of websites, certificate files and key stores for their SSL certificates expiry date.

### The Idea Behind

The monitoring tool was built as safety policy, to ensure that SSL certificates will not expire silently, with the risk of bringing down the associated systems along with them.

The monitoring tool has been designed to run as a Jenkins job and because its fast execution, it can be configured to run on a daily basis and it will check the SSL certificates based on a existing configuration.

In order to cover them all, the monitoring tool has a number of way that will allow configuring the certificates as following:

1. The domains list file. Text based file where domain URL's must be added. The monitoring tool will parse the list file and for each entry will extract the check the validity of the SSL certificate. The URL's must be added in the list, along with the default SSL port which is 443. E.G. nba.com 443.
2. A certificate file using PEM or PKCS12 format. This is usually applicable for server or Tomcat key store SSL certificates that cannot be parsed through a public URL. This kind of certificates are used to secure REST webservices communication. The certificate files must be added into the monitoring tool as soon as they are renewed or created on their corresponding servers.
3. A Java keys tore type of file: JKS. The monitoring tool is going to scan all the certificates inside the key store and will monitor their expiry date.

The same approach must be applied as to the PEM or PKCS12 certificates where the JKS file must be added to the monitoring tool certificate-stores folder as soon as it is setup or updated on its corresponding server.

The monitoring tool has been designed with an alert system that will inform, via email, a configurable list of recipients, when the SSL certificates are reaching their expiry date. The emails will contain an HTML based report that will contain useful information about the SSL certificate that is going to expire, the services that will be affected by that as well as other useful information about the certificate details.

The alerts system and reports can be categorised as following:

##### 1. Green alert and report

This alert and its corresponding report is due to be fired, when the SSL certificates expiry date will reach the value of 7 days. The number of days is configurable and parameterized in the Jenkins job, therefore it can be easily changed and adapted to custom needs and requirements.

The green report has an HTML template base that will be dynamically parsed, when the Jenkins job runs and a "Search and Replace" mechanism will ensure that all the template placeholders will be replaced with the required values. A sample screenshot of the green report looks like the following:

<img src="https://github.com/graadi/ssl-certificates-monitor-bash-script/blob/main/images/green-report.png" />

##### 2. Orange alert and report

This alert and its corresponding report is due to be fired, when the SSL certificates expiry date will reach the value of 3 days. The number of days is configurable and parameterized in the Jenkins job, therefore it can be easily changed and adapted to custom needs and requirements.

The orange report has an HTML template base that will be dynamically parsed, when the Jenkins job runs and a "Search and Replace" mechanism will ensure that all the template placeholders will be replaced with the required values. A sample screenshot of the green report looks like the following:

<img src="https://github.com/graadi/ssl-certificates-monitor-bash-script/blob/main/images/orange-report.png" />

##### 3. Red alert and report

This alert and its corresponding report is due to be fired, on the day when the SSL certificates expires. This is the last alert and the most critical one, indicating that a SSL certificate has expired. Ideally the system will never issue such an alert as the there will be enough time for the SSL certificates to be renewed, from the moment when the first green alert is fired.

The red report has an HTML template base that will be dynamically parsed, when the Jenkins job runs and a "Search and Replace" mechanism will ensure that all the template placeholders will be replaced with the required values. A sample screenshot of the green report looks like the following:

<img src="https://github.com/graadi/ssl-certificates-monitor-bash-script/blob/main/images/red-report.png" />

##### 4. Monthly aggregated report

This is an informative alert and email, that will be sent on a monthly basis and it will contain a snapshot of all the existing (that will be found in the configuration folder - the certificates-store) SSL certificates, along with their expiry date. An example of the monthly aggregated report looks like the following:

<img src="https://github.com/graadi/ssl-certificates-monitor-bash-script/blob/main/images/aggregated-report.png" />

### Bash Script and Configuration

The Bash script is the core of the monitoring tool as it performs the critical operations of inspecting the certificates details, extracting and assessing the expiry date, along with other useful information that populates the email reports.

The repository has the following structure:

| Name               | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| certificate-stores | The folder that stores the certificate files, keystore files as well as the domain list file. The certificate-stores/domains.dl is a text file that contains a list of all domains, in the following format: domainname 443 |
| config             | Contains the configuration file(s). Currently it stores the configuration files that persists the aggregated report start date value. |
| html               | The location of the e-mail HTML report templates. They are categorised by the report type: green, orange and red. The main html files will contain the report container and for each main html file, there is a corresponding folder that contains the templates for report list and the list item details. The aggregated report template is also in this location. |
| jq                 | JSON post-processing tool that is used to format the Bash script json output, for better readability |

The script uses external tools to inspect and extract SSL certificate details as following: openssl, Java keytool, perl, date, sed and many more. The script follows a procedural approach and has a number of functions where the core operations are implemented and a main one which is the entry point at the execution time. The following diagram will explain the execution flow of the script:

<img src="https://github.com/graadi/ssl-certificates-monitor-bash-script/blob/main/images/bash-script-diagram.png" />
