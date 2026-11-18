package gien.release_test

import rego.v1
import data.gien.release

test_default_deny_without_input if {
  release.allow == false
}
