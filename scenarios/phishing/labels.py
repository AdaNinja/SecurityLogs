#!/usr/bin/env python3
"""
钓鱼攻击场景标签函数
"""

from logger_utils import inject_label, log_attack_event

def recon():
    """Reconnaissance 阶段标签"""
    inject_label("phase=Reconnaissance")
    log_attack_event("phishing_recon_start")

def deliver():
    """Delivery 阶段标签"""
    inject_label("phase=Delivery")
    log_attack_event("phishing_delivery_start")

def exploit():
    """Exploitation 阶段标签"""
    inject_label("phase=Exploitation")
    log_attack_event("phishing_exploitation_start")

def credential_theft():
    """凭证窃取事件标签"""
    inject_label("attack_type=credential_theft")
    log_attack_event("credential_theft_attempt")

def email_opened():
    """邮件打开事件标签"""
    inject_label("event=email_opened")
    log_attack_event("phishing_email_opened")

def link_clicked():
    """链接点击事件标签"""
    inject_label("event=link_clicked")
    log_attack_event("phishing_link_clicked")

def form_submitted():
    """表单提交事件标签"""
    inject_label("event=form_submitted")
    log_attack_event("phishing_form_submitted")

def c2_communication():
    """C2通信事件标签"""
    inject_label("event=c2_communication")
    log_attack_event("c2_credential_exfil")
