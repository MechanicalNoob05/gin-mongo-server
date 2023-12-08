# Gin-Mongo-Server

This project provides a foundational setup for building a server using Golang and MongoDB, offering a starting point that developers can customize to meet their specific requirements. By incorporating the Gin-Gonic framework for routing and MongoDB for data storage, the project establishes a solid structure for creating RESTful APIs. Developers can leverage this bootstrap to streamline the development process, focusing on business logic rather than the intricacies of server setup. The modular design allows for easy extension and modification, making it an ideal starting point for a wide range of web applications and services. Whether building a small-scale project or a more complex system, this base setup encourages flexibility, scalability, and adherence to best practices in Go and MongoDB development.

##### Table of Contents

- Overview
- Prerequisites
- Installation
- Usage
- Configuration
- Endpoints
- License
- Reference

### Overview

This project serves as a basic bootstrap for a server using Golang and MongoDB, which can be further modified to suit specific requirements.

### Prerequisites

List any prerequisites or dependencies users need to have before getting started

- Go
- Mongodb

### Installation

Provide step-by-step instructions to set up and run the project locally.

```bash
# Clone the repository
git clone https://github.com/MechanicalNoob05/gin-mongo-server.git

# Navigate to the project directory
cd gin-mongo-server
```
```bash
touch .env

# Add your mongodb url in .env with variable name MONGOURI i.e.MONGOURI=mongodb+srv://Username:password@cluster0.e5akf.mongodb.net/golangDB?retryWrites=true&w=majority

```

### Usage

```bash
# Install dependencies
go mod tidy

# Build and run the server
go run main.go
```
### Endpoints

List and describe the API endpoints your server exposes.

|   Method  | Route         |    
| --------  | --------      | 
|POST       |/user          |
|GET        |/user/:userId  |
|PUT        |/user/:userId  |
|DELETE     |/user/:userId  |
|GET        |/users         |

### Reference

This project is based on the guide Build a REST API with Go-lang and MongoDB (Gin-Gonic Version) by [Demola Malomo](https://dev.to/malomz). The guide provides a detailed walk through and can be used as a reference for further customisation.
