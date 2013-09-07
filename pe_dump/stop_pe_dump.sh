#!/bin/bash


ps ax|grep pe_dump|grep dumps|awk '{print $1}'|xargs sudo kill
