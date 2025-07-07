#!/usr/bin/env python3
"""
Phishing attack scenario label functions
"""

from logger_utils import inject_label, log_attack_event

def recon():
    """Reconnaissance phase label"""
    inject_label("phase=Reconnaissance")
    log_attack_event("phishing_recon_start")

def deliver():
    """Delivery phase label"""
    inject_label("phase=Delivery")
    log_attack_event("phishing_delivery_start")

def exploit():
    """Exploitation phase label"""
    inject_label("phase=Exploitation")
    log_attack_event("phishing_exploitation_start")

def credential_theft():
    """Credential theft event label"""
    inject_label("attack_type=credential_theft")
    log_attack_event("credential_theft_attempt")

def email_opened():
    """Email opened event label"""
    inject_label("event=email_opened")
    log_attack_event("phishing_email_opened")

def link_clicked():
    """Link clicked event label"""
    inject_label("event=link_clicked")
    log_attack_event("phishing_link_clicked")

def form_submitted():
    """Form submitted event label"""
    inject_label("event=form_submitted")
    log_attack_event("phishing_form_submitted")

def c2_communication():
    """C2 communication event label"""
    inject_label("event=c2_communication")
    log_attack_event("c2_credential_exfil")
