import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

def normalize_answer(ans):
    ans = ans.strip().lower()
    if ans.endswith('z'):
        ans = ans[:-1]
    return ans

def compare_answers(expected, actual):
    e = normalize_answer(expected)
    a = normalize_answer(actual)
    if e == a:
        return True
    
    # check time parts
    # e.g., "2026-10-03t02:19:51" vs "02:19:51"
    if "t" in e:
        e_time = e.split("t")[-1]
        if a == e_time:
            return True
    if "t" in a:
        a_time = a.split("t")[-1]
        if e == a_time:
            return True
            
    # space instead of T for time
    if " " in e:
        e_time = e.split(" ")[-1]
        if a == e_time:
            return True
    if " " in a:
        a_time = a.split(" ")[-1]
        if e == a_time:
            return True

    return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--tester", required=True)
    parser.add_argument("--condition", required=True, choices=["manual", "tool"])
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    
    csv_path = Path("evaluation/triage_results.csv")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    
    if not csv_path.exists():
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["scenario", "tester", "condition", "question_id", "seconds", "correct", "notes"])
            
    if not args.force:
        with open(csv_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row["scenario"] == args.scenario and row["tester"] == args.tester and row["condition"] == args.condition:
                    print(f"Error: session for {args.scenario} / {args.tester} / {args.condition} already exists.")
                    print("Use --force to run anyway.")
                    sys.exit(1)
                    
    gt_file = Path(f"scenarios/{args.scenario}/ground_truth.json")
    if not gt_file.exists():
        print(f"Error: {gt_file} not found.")
        sys.exit(1)
        
    with open(gt_file, "r", encoding="utf-8") as f:
        gt = json.load(f)
        
    questions = gt.get("triage_questions", [])
    if not questions:
        print("No triage_questions in ground truth.")
        sys.exit(0)
        
    total_seconds = 0
    correct_count = 0
    
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for i, q_obj in enumerate(questions):
            q = q_obj["q"]
            expected = q_obj["answer"]
            
            print(f"\nQ{i+1}: {q}")
            input("Press Enter to START the stopwatch...")
            start_time = time.perf_counter()
            
            input("Press Enter to STOP the stopwatch...")
            end_time = time.perf_counter()
            
            seconds = round(end_time - start_time, 1)
            total_seconds += seconds
            
            actual = input("Your answer: ")
            
            is_correct = compare_answers(expected, actual)
            if is_correct:
                print("CORRECT")
                correct_count += 1
            else:
                print("INCORRECT")
                
            print(f"Expected answer: {expected}")
            
            notes = input("Optional notes: ")
            
            writer.writerow([args.scenario, args.tester, args.condition, i+1, seconds, is_correct, notes])
            f.flush()
            
    print("\nSession summary:")
    print(f"Total time: {total_seconds:.1f} seconds")
    print(f"Correct answers: {correct_count}/{len(questions)}")

if __name__ == "__main__":
    main()
