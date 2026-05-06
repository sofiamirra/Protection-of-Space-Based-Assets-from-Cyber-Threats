# Cybersecurity and National Defence -- Technical Project

## Topic B -- Cyber Risk Prioritization and Treatment Tool

---

## Group Members

- Pietro Surname -- s335801
- Lorenzo Surname -- s341841
- Sofia Mirra -- s329259
- Luca Tartarini -- s338507

---

## Project Description
This project implements a deterministic Cyber Risk Prioritization and Treatment Tool. 

The program reads JSON input files representing organizational assets, a catalog of security controls, and specific threat scenarios. For each scenario, the engine calculates the initial risk and the residual risk by applying the mitigating effects of currently deployed controls. 

If the residual risk exceeds the asset's acceptable threshold, the tool employs a greedy algorithm to recommend additional, un-deployed controls applicable to the specific threat. The program outputs a structured JSON report detailing the risk posture and treatment results for each scenario, sorted by priority (unacceptable risks first, ordered by highest residual risk).

---

## Project Structure
- `main.py`: main program executing the risk analysis engine.
- `src/`: Python modules used by the program (includes the provided `loader.py`).
- `input/`: directory containing the input files (`assets.json`, `security_controls.json`, `scenarios.json`).
- `output/`: directory where the generated `result.json` will be saved.
- `README.md`: this documentation file.
- `requirements.txt`: list of required Python libraries.

---

## Python Version
Python 3.8 or higher.

---

## Required Libraries
This project uses **only the Python standard library** (`json`, `argparse`, `pathlib`, `os`). 

The `requirements.txt` file is included for structural compliance but remains empty as no external dependencies (e.g., pandas, numpy) are required to execute the core logic.

---

## Creating a Virtual Environment
A virtual environment is recommended in order to install the project libraries in an isolated way (though optional for this standard-library-only project).

### Linux / macOS
```bash
python -m venv .venv
source .venv/bin/activate
