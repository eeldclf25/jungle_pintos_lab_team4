CHOICE=76

for i in {1..100}; do
    res="$(printf "%s\n" "$CHOICE" | bash select_test.sh -q | grep -E '^(PASS|FAIL)$')"
    echo "run=$i test=$CHOICE result=${res:-NONE}" >> .while_test_status
done