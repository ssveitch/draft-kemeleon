---
###
# Internet-Draft Markdown Template
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
title: "Kemeleon Encodings"
abbrev: "Kemeleon"
category: info

docname: draft-kemeleon
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: AREA
workgroup: WG Working Group
keyword:
 - encoding
 - key encapsulation mechanism
venue:
  group: WG
  type: Working Group
  mail: WG@example.com
  arch: https://example.com/WG
  github: ssveitch/draft-kemeleon
  latest: https://example.com/LATEST

author:
 -
    fullname: Felix Günther
    organization: IBM Research - Zurich
    email: mail@felixguenther.info

 -
    fullname: Douglas Stebila
    organization: University of Waterloo
    email: dstebila@uwaterloo.ca

 -
    fullname: Shannon Veitch
    organization: ETH Zurich
    email: shannon.veitch@inf.ethz.ch

normative:

informative:


--- abstract

This document specifies algorithms for encoding ML-KEM public keys and ciphertexts as random bitstrings. This document is a product of the Crypto Forum Research Group (CFRG) in the IRTF.

--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
