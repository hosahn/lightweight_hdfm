#SBOM Analyzer


(Disclaminer: ONLY function descriptions in this project are written by a LLM model to increase the readability of the project)

> **Hybrid Decision Model for Software Supply Chain Security**
> *Built with Hexagonal Architecture (Ports & Adapters)*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.95%2B-green)
![Architecture](https://img.shields.io/badge/Architecture-Hexagonal-orange)

## Overview

**HDM** is a next-generation Software Bill of Materials (SBOM) analyzer. Unlike traditional scanners that only count vulnerabilities, HDFM prioritizes them based on a **Hybrid Decision-Fusion Model**.

It combines topological analysis (how deep/central a component is in your graph) with real-time threat intelligence (EPSS, CISA KEV) and mathematical weighting (Shannon Entropy) to tell you not just *what* is vulnerable, but *what matters right now*.

## Key Features

* **Hexagonal Architecture:** strict separation of concerns between Core Domain, Application Logic, and Infrastructure.
* **Real-time Vulnerability Scanning:** Integrates with **OSV.dev** to scan SBOMs via PURL (Package URL).
* **Contextual Prioritization (HDFM Algorithm):**
    * **TCS (Topological Criticality Score):** Calculates dependency depth and centrality using Graph Theory.
    * **Threat Intel Fusion:** Fetches **EPSS** (Exploit Prediction Scoring System) and **CISA KEV** (Known Exploited Vulnerabilities) status.
    * **Dynamic Weighting:** Uses **Shannon Entropy** to auto-adjust scoring weights based on the specific data distribution of the SBOM.
* **Modern Tech Stack:** FastAPI, SQLAlchemy 2.x, NetworkX, Pandas, TailwindCSS.

## Project Structure

```text
.
├── application/           # Application Layer (Orchestration)
│   ├── service/           # Ingestion & Prioritization Services
│   └── dtos.py            # Data Transfer Objects
├── core/                  # Domain Layer (Business Logic)
│   ├── entities.py        # Domain Models (Component, Vulnerability)
│   ├── hdfm_model.py      # The HDFM Scoring Algorithm
│   └── interface.py       # Ports (Abstract Interfaces)
├── infrastructure/        # Infrastructure Layer (Adapters)
│   ├── api/               # External Clients (OSV, Threat Intel)
│   ├── graph/             # NetworkX Adapter & Repositories
│   └── persistence/       # SQLite Database Config
├── main.py                # Composition Root & FastAPI Entry Point
└── requirements.txt       # Dependencies