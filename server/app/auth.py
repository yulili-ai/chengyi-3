import hashlib
import secrets
import smtplib
import ssl
from email.message import EmailMessage
from datetime import timedelta

from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select

from app.conversation import authenticate_session
from app.models import AuthSession, EmailVerificationCode, PotteryProject, User, utcnow


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def send_verification_email(email: str, code: str, settings):
    if not settings.smtp_username.strip() or not settings.smtp_password.get_secret_value():
        raise HTTPException(422, "QQ 邮箱 SMTP 尚未配置，请先填写邮箱和授权码")
    message = EmailMessage()
    message["Subject"] = "承艺登录验证码"
    message["From"] = settings.smtp_from.strip() or settings.smtp_username.strip()
    message["To"] = email
    message.set_content(f"你的承艺登录验证码是：{code}\n验证码 10 分钟内有效，请勿转发给他人。")
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, context=context, timeout=15) as smtp:
            smtp.login(settings.smtp_username.strip(), settings.smtp_password.get_secret_value())
            smtp.send_message(message)
    except (smtplib.SMTPException, OSError, ssl.SSLError):
        raise HTTPException(502, "验证码邮件暂时发送失败，请稍后重试") from None


def request_email_code(db, email: str, settings):
    email = email.strip().lower()
    db.query(EmailVerificationCode).filter(
        EmailVerificationCode.email == email,
        EmailVerificationCode.consumed_at.is_(None),
    ).update({EmailVerificationCode.consumed_at: utcnow()})

    code = "".join(str(secrets.randbelow(10)) for _ in range(6))
    record = EmailVerificationCode(
        email=email,
        code_hash=hash_secret(code),
        expires_at=utcnow() + timedelta(minutes=10),
        attempts=0,
    )
    db.add(record)
    db.commit()
    result = {"expires_in": 600}
    if settings.smtp_enabled:
        send_verification_email(email, code, settings)
    elif settings.environment == "development":
        result["development_code"] = code
    return result


def verify_email_code(db, payload, settings):
    email = payload.email.strip().lower()
    record = db.scalar(
        select(EmailVerificationCode)
        .where(
            EmailVerificationCode.email == email,
            EmailVerificationCode.consumed_at.is_(None),
        )
        .order_by(EmailVerificationCode.created_at.desc())
    )
    if not record or record.expires_at <= utcnow():
        raise HTTPException(400, "验证码已过期，请重新获取")
    if record.attempts >= 5:
        raise HTTPException(429, "验证码尝试次数过多，请重新获取")
    record.attempts += 1
    if not secrets.compare_digest(record.code_hash, hash_secret(payload.code)):
        db.commit()
        raise HTTPException(400, "验证码不正确")

    record.consumed_at = utcnow()
    user = db.scalar(select(User).where(User.email == email))
    if not user:
        user = User(email=email, status="active")
        db.add(user)
        db.flush()

    migrate_guest_projects(db, user, payload.guest_projects)
    user.last_login_at = utcnow()

    token = secrets.token_urlsafe(36)
    auth_session = AuthSession(
        user_id=user.id,
        token_hash=hash_secret(token),
        expires_at=utcnow() + timedelta(days=30),
    )
    db.add(auth_session)
    db.commit()
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 30 * 24 * 3600,
        "user": {"id": user.id, "email": user.email},
    }


def migrate_guest_projects(db, user: User, guest_projects):
    for item in guest_projects:
        project = db.get(PotteryProject, item.project_id)
        if not project:
            continue
        authenticate_session(db, project.session_id, item.session_token)
        project.owner_user_id = user.id


def authenticate_user(db, authorization: str, settings):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "请先登录账号")
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(401, "登录已失效，请重新登录")
    session = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_secret(token)))
    if not session or session.revoked_at is not None or session.expires_at <= utcnow():
        raise HTTPException(401, "登录已失效，请重新登录")
    user = db.get(User, session.user_id)
    if not user or user.status != "active":
        raise HTTPException(401, "账号不可用，请重新登录")
    return user, session


def logout_user(db, authorization: str, settings):
    user, session = authenticate_user(db, authorization, settings)
    session.revoked_at = utcnow()
    db.commit()
