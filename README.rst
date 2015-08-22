===============
python-particle
===============

A python wrapper around the Particle Cloud API (http://particle.io)

==================
Installation Notes
==================

Installable directly via pip. However some systems might need to install requests[security] if they get the InsecurePlatformWarning. That hasn't been included in the requirements by default because it may not be required on all platforms.


===========================
Local configuration Support
===========================

As of v0.2 local support is available to configure devices over serial.


=====
Tests
=====

Tests coming soon. Except tests for this particular package are going to be highly localized. You will need to provide a valid, particle username, password and not to mention a proper device ID that can be used to test the claim and request features
