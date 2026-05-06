import argparse
import json
from pathlib import Path

from src.loader import load_json


def compute_residual(likelihood, impact, total_l_red, total_i_red):
    # Calculate residual risk ensuring parameters never drop below 1
    res_l = max(1, likelihood - total_l_red)
    res_i = max(1, impact - total_i_red)
    return res_l * res_i, res_l, res_i


def calculate_reductions(controls_ids, controls_dict):
    # Calculate total likelihood and impact reduction from deployed controls
    total_l_red = 0
    total_i_red = 0
    valid_controls_names = []
    invalid_controls = []

    # Iterate the list of applied controls and calculate the total protection
    for cid in controls_ids:
        if cid in controls_dict:
            ctrl = controls_dict[cid]
            total_l_red += ctrl.get('likelihood_reduction', 0)
            total_i_red += ctrl.get('impact_reduction', 0)
            valid_controls_names.append(ctrl['name'])
        else:
            invalid_controls.append(cid) # if the id is not found

    return total_l_red, total_i_red, valid_controls_names, invalid_controls


def process_scenarios(assets_dict, controls_dict, scenarios_list):
    # Core engine processing each threat scenario against deployed and available controls
    results = []
    summary = {
        "total_scenarios": 0,
        "acceptable_scenarios": 0,
        "not_acceptable_scenarios": 0,
        "highest_residual_risk": 0
    }

    for scenario in scenarios_list:
        summary["total_scenarios"] += 1
        asset = assets_dict.get(scenario['asset_id'])

        # Skip scenarios with undefined assets
        if not asset:
            results.append({
                "scenario_id": scenario['id'],
                "status": "invalid",
                "details": "Asset not found in catalog"
            })
            continue

        initial_risk = scenario['likelihood'] * scenario['impact']
        deployed_ids = scenario.get('deployed_controls', [])

        total_l_red, total_i_red, valid_names, invalid_refs = calculate_reductions(deployed_ids, controls_dict)
        residual_risk, res_l, res_i = compute_residual(
            scenario['likelihood'], scenario['impact'], total_l_red, total_i_red
        )

        if residual_risk > summary["highest_residual_risk"]:
            summary["highest_residual_risk"] = residual_risk

        threshold = asset['risk_threshold']

        result = {
            "scenario_id": scenario['id'],
            "asset_id": asset['id'],
            "asset_name": asset['name'],
            "threat": scenario['threat'],
            "exposure": scenario['exposure'],
            "initial_risk": initial_risk,
            "deployed_controls": valid_names,
            "residual_risk": residual_risk,
            "acceptable_threshold": threshold
        }

        if invalid_refs:
            result["invalid_control_references"] = invalid_refs

        if residual_risk <= threshold:
            summary["acceptable_scenarios"] += 1
            result["status"] = "acceptable"
            result["recommended_controls"] = []
            result["projected_risk_after_recommendation"] = residual_risk
            result["treatment_result"] = "already_acceptable"
        else:
            summary["not_acceptable_scenarios"] += 1
            result["status"] = "not_acceptable"

            # Greedy logic for unacceptable risks
            available_controls = []
            for cid, ctrl in controls_dict.items():
                if cid not in deployed_ids and scenario['threat'] in ctrl.get('applicable_threats', []):
                    power = ctrl.get('likelihood_reduction', 0) + ctrl.get('impact_reduction', 0)
                    available_controls.append({
                        "id": cid,
                        "name": ctrl['name'],
                        "power": power,
                        "l_red": ctrl.get('likelihood_reduction', 0),
                        "i_red": ctrl.get('impact_reduction', 0)
                    })

            # Sort controls by highest reduction power
            available_controls.sort(key=lambda x: x['power'], reverse=True)

            recommended = []
            projected_risk = residual_risk

            # Iteratively apply controls until risk drops below threshold
            for ctrl in available_controls:
                if projected_risk <= threshold:
                    break

                recommended.append(ctrl['name'])

                sim_l_red = total_l_red + sum(c['l_red'] for c in available_controls if c['name'] in recommended)
                sim_i_red = total_i_red + sum(c['i_red'] for c in available_controls if c['name'] in recommended)

                projected_risk, _, _ = compute_residual(
                    scenario['likelihood'], scenario['impact'], sim_l_red, sim_i_red
                )

            result["recommended_controls"] = recommended
            result["projected_risk_after_recommendation"] = projected_risk

            if projected_risk <= threshold:
                result["treatment_result"] = "threshold_met"
            else:
                result["treatment_result"] = "threshold_not_met"

        results.append(result)

    # Sort scenarios: unhandled risks first, ordered by descending severity
    results.sort(key=lambda x: (x.get('status') == 'not_acceptable', x.get('residual_risk', 0)), reverse=True)

    for idx, res in enumerate(results):
        res["priority"] = idx + 1

    return {"summary": summary, "risk_results": results}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input directory")
    parser.add_argument("--output", required=True, help="Output JSON file")
    return parser.parse_args()


def main():
    args = parse_args()
    input_dir = Path(args.input)

    # Load data using the provided loader
    assets = load_json(input_dir / "assets.json")
    controls = load_json(input_dir / "security_controls.json")
    scenarios = load_json(input_dir / "scenarios.json")

    # Convert lists to dictionaries for quicker lookup times
    assets_dict = {a['id']: a for a in assets.get('assets', [])}
    controls_dict = {c['id']: c for c in controls.get('security_controls', [])}
    scenarios_list = scenarios.get('scenarios', [])

    # Execute the risk analysis engine
    result = process_scenarios(assets_dict, controls_dict, scenarios_list)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    main()