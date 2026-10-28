from autogen_version.agents import run_investigation
from shared.schemas import Alert

if __name__ == "__main__":
    inv = run_investigation(Alert(title="AutoGen investigation",
                                  target="http://localhost:5000"))
    print(inv.model_dump_json(indent=2))
