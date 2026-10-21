#!/usr/bin/env python3
"""Send an SDK CI failure notification using repository SMTP secrets."""

from __future__ import annotations

from email.message import EmailMessage
import os
import smtplib
import ssl


def _required_environment_variable(name: str) -> str:
  value = os.environ.get(name, "").strip()
  if not value:
    raise RuntimeError(f"Required environment variable {name} is not set.")
  return value


def _recipients() -> list[str]:
  recipients = [
      recipient.strip()
      for recipient in _required_environment_variable(
          "CI_FAILURE_RECIPIENTS"
      ).split(",")
      if recipient.strip()
  ]
  if not recipients:
    raise RuntimeError("CI_FAILURE_RECIPIENTS does not contain an address.")
  return recipients


def _message(sender: str, recipients: list[str]) -> EmailMessage:
  repository = _required_environment_variable("CI_REPOSITORY")
  workflow_name = _required_environment_variable("CI_WORKFLOW_NAME")
  run_url = _required_environment_variable("CI_RUN_URL")
  branch = os.environ.get("CI_HEAD_BRANCH", "unknown")
  commit = os.environ.get("CI_HEAD_SHA", "unknown")
  short_commit = commit[:12]

  message = EmailMessage()
  message["Subject"] = (
      f"[CI failure] {repository}: {workflow_name} "
      f"({branch} @ {short_commit})"
  )
  message["From"] = sender
  message["To"] = ", ".join(recipients)
  message.set_content(
      "\n".join(
          (
              f"Workflow: {workflow_name}",
              f"Repository: {repository}",
              f"Event: {os.environ.get('CI_EVENT', 'unknown')}",
              f"Branch: {branch}",
              f"Commit: {commit}",
              f"Actor: {os.environ.get('CI_ACTOR', 'unknown')}",
              "Conclusion: failure",
              "",
              f"View the failed run: {run_url}",
          )
      )
  )
  return message


def main() -> None:
  host = _required_environment_variable("SMTP_HOST")
  username = _required_environment_variable("SMTP_USERNAME")
  password = _required_environment_variable("SMTP_PASSWORD")
  sender = os.environ.get("SMTP_FROM", "").strip() or username
  port = int(os.environ.get("SMTP_PORT", "").strip() or "465")
  security = os.environ.get("SMTP_SECURITY", "").strip().lower() or "ssl"
  recipients = _recipients()
  message = _message(sender, recipients)
  tls_context = ssl.create_default_context()

  if security == "ssl":
    with smtplib.SMTP_SSL(
        host, port, timeout=30, context=tls_context
    ) as smtp:
      smtp.login(username, password)
      smtp.send_message(message)
    return

  if security == "starttls":
    with smtplib.SMTP(host, port, timeout=30) as smtp:
      smtp.starttls(context=tls_context)
      smtp.login(username, password)
      smtp.send_message(message)
    return

  raise RuntimeError(
      "SMTP_SECURITY must be either 'ssl' or 'starttls'."
  )


if __name__ == "__main__":
  main()
