#!/usr/bin/bash

./sunset -sample samples/$1 -time $2 -gh-token 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
exps_dir=$(ls -td experiments/* | head -n 1)
cat $exps_dir/workflow* > $exps_dir/workflow_tot.yml
python3 wfExtractor.py --wf $exps_dir/workflow_tot.yml --dest $exps_dir --token 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
python3 wfAnalyzer.py --src $exps_dir --dest $exps_dir/$1_report.json --token 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

