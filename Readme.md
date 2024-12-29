# Dock[er]Inv[entory]

## Description
DockInv helps to get an overview of used docker images across multiple servers. It uses trivy and xeol to find end-of-live or vulnerable docker images. It consists of two parts: dockinv agent and dockinv server. The agent is a simple python script that gives limited external access to the containers endpoint of the docker api. The server is a web application that collects the information and displays it in a web interface.

## Tech Stack
- **Flask** as web framework
- **Celery** as background task runner
- **Docker** as deployment platform
- **Trivy** as vulnerability scanner
- **Xeol** as end-of-life scanner
- **SQLite** as database

## Keywords
- Docker Security Dashboard
- Docker Inventory
- Docker scan full host
- Docker scan all images
