# GHAST
> An automatic tool for the security assessment of GitHub Actions, leveraging the Sunset security framework.

**GHAST** identifies code repositories in the software supply chain and collects all the workflows in these repositories. Then, it provides security evaluation of the workflows.

:warning: **GHAST** relies on Sunset, so it automatically analyses _only_ python-based projects. However, GHAST scripts can still be used to analyze workflow files directly. Sunset is a work-in-progress project that will support other languages in the short term.

## ❱ Setup
This prototype is compatible with Ubuntu 20.04 and Python 3.8.

Also, GHAST needs a running Neo4j server.
To execute Neo4j, download the Ubuntu tar file from https://neo4j.com/download-center/#community, open a terminal and then execute the command `./bin/neo4j console`

The server should run on localhost using the default port (7474). The first time you need to set log in using a browser to setup the username and the password. You can use the default user "Neo4j" and set the password to "password".

Also you need a valid GitHub Token. To generate a GitHub token please refer to https://docs.github.com/en/enterprise-server@3.4/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token.

Inside the scored folder create an environment in python3 and install the requirements using the following command: `python3 -m venv venv`

Activate the environment using `source venv/bin/activate`, then give the execution permissions to the run script using `chmod +x run.sh`.

Install the requirements using the command `pip install -r requirements.txt`

## ❱ Execution

First, you must copy the folder of the software under test inside of the `samples` directory.

Then you need to copy the GitHub token inside the run.sh file by replacing the tag `<ghtoken>`.
We chose to handle tokens this way to allow the use of multiple tokens.

After that, execute the following command: `run.sh <project_name> <timeout>`

where `<project_name>` is the name of the directory copied in the `samples` directory and `<timeout>` is the maximum time (expressed in minutes) allowed to perform the analysis. The suggested value for `<timeout>` is 20.

At the end of the computation, the results will be stored in a subfolder of the `experiments` directory named `_mm-dd-yyyy_HH:MM:ss\_<project_name>_`. The folder will contain a set of artifacts generated by GHAST and a file named `<project_name>_report.json` containing the security issues identified.

## ❱ License

This tool is available under AGPL license for open-source projects.

A detail of the policy and agreements is available in the [LICENSE](LICENSE) file.

## ❱ Credits

This software was developed for research purposes at the Computer Security Lab ([CSecLab](https://csec.it/)), hosted at DIBRIS, University of Genova.


<div align="left"

[![Unige](https://intranet.dibris.unige.it/img/logo_unige.gif)](https://unige.it/en/)
[![Dibris](https://intranet.dibris.unige.it/img/logo_dibris.gif)](https://www.dibris.unige.it/en/)

</div>

## ❱ Team

* [Giacomo Benedetti](https://csec.it/people/giacomo_benedetti/) - Ph.D Student & Developer
* [Luca Verderame](https://csec.it/people/luca_verderame/) - Postdoctoral Researcher
* [Alessio Merlo](https://csec.it/people/alessio_merlo/) - Faculty Member