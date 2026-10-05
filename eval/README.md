# Evaluation scripts

| script | what it does | needs |
|---|---|---|
| `simulate.py` | simulated beacons and non-beacon traffic, plain vs beacon-hunter scoring | nothing |
| `iot23.py` | ranks the labeled C&C pairs in IoT-23 malware captures | the logs below |
| `plot.py` | redraws every README figure in dark and light versions | the logs, for the two real-traffic figures |

Results and discussion: [`docs/evaluation.md`](../docs/evaluation.md).

## Getting the IoT-23 logs

Only the labeled Zeek `conn.log` files are used: plain text, no packet captures, no malware binaries. About 29 MB in total. They go in `eval/data/`, which git ignores.

```bash
mkdir -p eval/data
base=https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios
for s in CTU-IoT-Malware-Capture-3-1 CTU-IoT-Malware-Capture-8-1 CTU-IoT-Malware-Capture-20-1 \
         CTU-IoT-Malware-Capture-21-1 CTU-IoT-Malware-Capture-34-1 CTU-IoT-Malware-Capture-42-1 \
         CTU-IoT-Malware-Capture-44-1 CTU-Honeypot-Capture-4-1 CTU-Honeypot-Capture-5-1; do
  curl -fsS -o "eval/data/$s.conn.log.labeled" "$base/$s/bro/conn.log.labeled"
done
python eval/iot23.py eval/data/*.labeled --show 5
```

Two format quirks the loader handles: the 2019 files separate the last three columns with spaces instead of tabs, and capture 34-1 (re-published in 2023) names the label column `det_label` instead of `detailed-label`.

IoT-23 is published by the Stratosphere Laboratory, CTU Prague, under CC BY. Citation: Agustin Parmisano, Sebastian Garcia, Maria Jose Erquiaga. *A labeled dataset with malicious and benign IoT network traffic.* https://www.stratosphereips.org/datasets-iot23
