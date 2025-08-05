# CHOICE=76

for test in {1..95}; do
    for i in {1..5}; do
        make clean
        make
        res="$(printf "%s\n" "$test" | bash select_test.sh -q | grep -E '^(PASS|FAIL)$')"
        echo "run=$i test=$test result=${res:-NONE}" >> .while_test_status
    done
done