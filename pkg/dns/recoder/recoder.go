/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Fed contains federation specific DNS code.
package recoder

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

var ErrExpectedKeyEqualsValue = errors.New("invalid format, must be key=value")

// ParseRecodersFlag parses the recoders command line flag. The
// flag is a comma-separated list of zero or more "name=label" pairs,
// e.g. "abc.com=127.0.0.1,manage01=192.168.0.1".
func ParseRecodersFlag(str string, recoders map[string]string) error {
	if strings.TrimSpace(str) == "" {
		return nil
	}

	for _, val := range strings.Split(str, ",") {
		splits := strings.SplitN(strings.TrimSpace(val), "=", 2)
		if len(splits) != 2 {
			return ErrExpectedKeyEqualsValue
		}

		domain := strings.TrimSpace(splits[0])
		ip := strings.TrimSpace(splits[1])
		if err := ValidateDomain(domain); err != nil {
			return err
		}
		if err := ValidateIP(ip); err != nil {
			return err
		}
		recoders[domain] = ip
	}

	return nil
}

// ValidateIP checks the validity of a ip.
func ValidateIP(ipstr string) error {
	if ip := net.ParseIP(ipstr); ip == nil {
		return fmt.Errorf("%q not a valid ip", ipstr)
	}
	return nil
}

// ValidateDomain checks the validity of a federation label.
func ValidateDomain(name string) error {
	// The federation domain name need not strictly be domain names, we
	// accept valid dns names with subdomain components.
	if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
		return fmt.Errorf("%q not a valid domain name: %q", name, errs)
	}
	return nil
}
