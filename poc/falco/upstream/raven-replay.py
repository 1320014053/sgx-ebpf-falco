"""Replay events with the upstream RAVEN engine and write its complete detections as JSONL."""

import argparse
import json

from raven.collector import ReplayFileCollector, TetragonCollector
from raven.correlation_engine import CorrelationEngine


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture")
    parser.add_argument("--format", choices=("replay", "tetragon"), default="replay")
    args = parser.parse_args()

    collector = (TetragonCollector(args.capture) if args.format == "tetragon"
                 else ReplayFileCollector(args.capture))
    engine = CorrelationEngine(tier="full")
    for event in collector.iter_events():
        engine.on_event(event)
    engine.settle_context(force=True)
    for detection in engine.detections:
        print(json.dumps(detection.to_dict(), ensure_ascii=False))


if __name__ == "__main__":
    main()
