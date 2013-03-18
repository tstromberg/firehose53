/*
   firehose53 - very quickly send a set of records to a list of DNS servers.

   Usage:

     firehose53 -f records.txt 8.8.8.8

     firehose53 -t=32 -j=4 -r "A google.com.,MX google.com." 8.8.8.8 8.8.4.4

   This uses 32 threads, and 4 processors to send these records to these IP's.

   Results are output as JSON for future analysis.

   The default configuration yields ~1666 QPS to localhost on a MacBook Air
   running Unbound with cached queries. Changing the flags to use 4 processors
   and 30 threads can increase the rate to 2500 QPS.
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
var numThreads = flag.Int("t", 8, "number of threads to use")
var inputRecords = flag.String("r", "A a.root-servers.net.",
	"Records to query")
var inputFile = flag.String("f", "", "File with records to query")
var quietMode = flag.Bool("q", true, "Quiet mode")

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
		if request.is_complete {
			break
		}
		result := query(request)
		results <- &result
	}
}

// For a given record string, add an item to the queue for each ip_port combination.
func queue_record(ip_ports []string, record string, queue chan<- *Request) {
	record_parts := strings.SplitN(record, " ", 2)
	for _, ip_port := range ip_ports {
		request := Request{ip_port, record_parts[0], record_parts[1], false}
		queue <- &request
	}
}

// For a comma delimited string, add each record for each ip_port combination to the queue
func queue_records_from_str(ip_ports []string, records string, queue chan<- *Request) {
	record_count := 0
	for _, record := range strings.Split(*inputRecords, ",") {
		record_count = record_count + 1
		queue_record(ip_ports, record, queue)
	}
	log.Printf("Read %d record(s) from string", record_count)
}

// For a path, add each record within for each ip_port combination to the queue
func queue_records_from_path(ip_ports []string, path string, queue chan<- *Request) {
	record_count := 0
	file, err := os.Open(path)
	if err != nil {
		log.Println(err)
		return
	}
	defer file.Close()
	buf := bufio.NewReader(file)
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			if err != io.EOF || len(line) > 0 {
				log.Println(err)
				return
			}
			break
		}
		record_count = record_count + 1
		queue_record(ip_ports, strings.TrimRight(line, "\n"), queue)
	}
	log.Printf("Read %d record(s) from %s", record_count, path)
}

// Watch the results channel for newly completed queuries, output summary in JSON to stdout
func display_results(results <-chan *Result, start_time time.Time) {
	counter := int64(0)
	error_counter := int64(0)
	for {
		result := <-results

		if result.is_complete {
			// TODO: add QPS calculation here
			log.Printf("%d answers / %d errors received\n", counter,
				error_counter)
			log.Printf("Duration: %s", time.Since(start_time))
			qps := counter / int64(time.Since(start_time)/time.Second)
			log.Printf("QPS: %d", qps)
			break
		}

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
	}
}

func main() {
	flag.Parse()
	runtime.GOMAXPROCS(*numCores)
	request_channel := make(chan *Request)
	result_channel := make(chan *Result)
	start_time := time.Now()

	// Create workers with blocking channels
	for i := 0; i < *numThreads; i++ {
		go start_worker(request_channel, result_channel)
	}

	// Send all proposed requests into the queue
	ip_ports := process_ip_args(flag.Args())

	// Display results as they come in.
	go display_results(result_channel, start_time)

	if *inputFile != "" {
		queue_records_from_path(ip_ports, *inputFile, request_channel)
	} else {
		queue_records_from_str(ip_ports, *inputRecords, request_channel)
	}

	// Tell all of the threads to die once the queue is closed
	for i := 0; i < *numThreads; i++ {
		request_channel <- &Request{is_complete: true}
	}
	result_channel <- &Result{is_complete: true}

	// TODO: Remove hack which makes sure log messages are emitted.
	time.Sleep(1 * time.Millisecond)
}
