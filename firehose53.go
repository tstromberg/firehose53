/*
   firehose53 - very quickly send a set of records to a list of DNS servers.

   Usage:

     firehose53 -f records.txt 8.8.8.8

     firehose53 -t=32 -j=4 -r "A google.com.,MX google.com." 8.8.8.8 8.8.4.4

   This uses 32 threads, and 4 processors to send these records to these IP's.

   Results are output as JSON for future analysis.

   The default configuration yields ~1450 QPS on a MacBook Air via localhost.
   Increasing the thread and processor count can double this number.
*/

// Copyright 2013 Thomas Stromberg. All rights reserved.
// Use of this source code is governed by a BSD-style
// license.

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

var numCores = flag.Int("j", 2, "number of cores to use")
var numThreads = flag.Int("t", 2, "number of threads to use")
var inputRecords = flag.String("r", "A a.root-servers.net.",
	"Records to query")
var inputFile = flag.String("f", "", "File with records to query")
var quietMode = flag.Bool("q", false, "Quiet mode")

type Request struct {
	Server      string
	RecordType  string
	RecordName  string
	is_complete bool
}

type Answer struct {
	Ttl    uint32
	Name   string
	String string
}

type Result struct {
	Request  Request
	Duration time.Duration
	Answers  []Answer
	Error    string

	is_complete bool
}

// Send a DNS query via UDP, configured by a Request object. If successful,
// stores response details in Result object, otherwise, returns Result object
// with an error string.
func query(request *Request) Result {
	var (
		record_type uint16
		ok          bool
	)
	m := new(dns.Msg)
	if record_type, ok = dns.StringToType[request.RecordType]; !ok {
		log.Println("Record type %s does not exist", request.RecordType)
		return Result{Error: "Unknown type"}
	}
	m.SetQuestion(request.RecordName, record_type)

	c := new(dns.Client)
	in, rtt, err := c.Exchange(m, request.Server)
	if err != nil {
		log.Println(err, request)
		return Result{
			Request:  *request,
			Duration: rtt,
			Error:    err.Error(),
		}
	}

	answers := make([]Answer, len(in.Answer))
	for i, rr := range in.Answer {
		answers[i] = Answer{
			Ttl:    rr.Header().Ttl,
			Name:   rr.Header().Name,
			String: rr.String(),
		}
	}
	return Result{
		Request:  *request,
		Duration: rtt,
		Answers:  answers,
	}
}

// Given a list of ips that may or may not have port pairs, return a list
// of valid looking ip:port pair strings.
func process_ip_args(ip_args []string) []string {
	ip_ports := make([]string, len(ip_args))
	for i, ip_port := range ip_args {
		if strings.Contains(ip_port, ":") == false {
			ip_port = ip_port + ":53"
		}
		ip_ports[i] = ip_port
	}
	return ip_ports
}

// Start a worker process that reads the request channel, sends DNS queries,
// and returns the results to the results channel.
func start_worker(queue <-chan *Request, results chan<- *Result) {
	for request := range queue {
		result := query(request)
		results <- &result
	}
}

// For a given record string, add an item to the queue for each ip_port combination.
func queue_record(ip_ports []string, record string, queue chan<- *Request) int64 {
	record_parts := strings.SplitN(record, " ", 2)
	count := int64(0)
	for _, ip_port := range ip_ports {
		request := Request{ip_port, record_parts[0], record_parts[1], false}
		queue <- &request
		count++
	}
	return count
}

// For a comma delimited string, add each record for each ip_port combination to the queue
func queue_records_from_str(ip_ports []string, records string, queue chan<- *Request) int64 {
	count := int64(0)
	for _, record := range strings.Split(*inputRecords, ",") {
		count = count + queue_record(ip_ports, record, queue)
	}
	log.Printf("Generated %d requests(s) from string", count)
	close(queue)
	return count
}

// For a path, add each record within for each ip_port combination to the queue
func queue_records_from_path(ip_ports []string, path string, queue chan<- *Request) int64 {
	count := int64(0)
	file, err := os.Open(path)
	if err != nil {
		log.Printf("Open error: %s", err)
		return count
	}
	defer file.Close()
	buf := bufio.NewReader(file)
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			if err != io.EOF || len(line) > 0 {
				log.Println(err)
				return count
			}
			break
		}
		added := queue_record(ip_ports, strings.TrimRight(line, "\n"), queue)
		count = count + added
	}
	log.Printf("Generated %d request(s) from %s", count, path)
	close(queue)
	return count
}

// Watch the results channel for newly completed queuries, output summary in JSON to stdout
func display_results(results <-chan *Result, start_time time.Time,
	expected_count int64) {
	counter := int64(0)
	error_counter := int64(0)
	for {
		result := <-results
		counter = counter + 1
		if result.Error != "" {
			error_counter = error_counter + 1
		}
		if *quietMode != true {
			output, err := json.Marshal(result)
			if err != nil {
				log.Println("Error: %s", err)
				break
			}
			fmt.Println(string(output))
		}
		if counter == expected_count {
			qps := (float64(counter) / float64(time.Since(start_time))) * float64(time.Second)
			log.Printf("%d answers / %d errors received in %s (%2.2f QPS)\n", counter,
				error_counter, time.Since(start_time), qps)
			return
		}

	}
}

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(*numCores)
	log.Printf("Started: %d cores, %d threads", *numCores, *numThreads)

	// TODO: Lower queue size once deadlock is worked out.
	request_channel := make(chan *Request, 50000)
	result_channel := make(chan *Result, 50000)

	for i := 0; i < *numThreads; i++ {
		go start_worker(request_channel, result_channel)
	}

	// Send all proposed requests into the queue
	ip_ports := process_ip_args(flag.Args())
	record_count := int64(0)
	start_time := time.Now()

	if *inputFile != "" {
		record_count = queue_records_from_path(ip_ports, *inputFile, request_channel)
	} else {
		record_count = queue_records_from_str(ip_ports, *inputRecords, request_channel)
	}
	if record_count == 0 {
		log.Printf("Nothing to do")
	} else {
		// Display results as they come in.
		display_results(result_channel, start_time, record_count)
	}
}
