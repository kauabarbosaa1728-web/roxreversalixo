import csv
import io
import os
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, abort, flash, redirect, render_template,
    request, session, url_for, Response, g
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)

app = Flask(__name__)

production = bool(os.environ.get("RENDER"))
secret = os.environ.get("SECRET_KEY")
database = os.environ.get("DATABASE_URL")

if production and (not secret or not database):
    raise RuntimeError(
        "Configure SECRET_KEY e DATABASE_URL no Render."
    )

if database and database.startswith("postgres://"):
    database = database.replace(
        "postgres://", "postgresql://", 1
    )

app.config.update(
    SECRET_KEY=secret or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=database or "sqlite:///reversa.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
    SESSION_COOKIE_NAME="reversa_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=production,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=1024 * 1024,
)

db = SQLAlchemy(app)

STATUSES = [
    "Recebido",
    "Em teste",
    "Aprovado",
    "Para conserto",
    "Lixo eletrônico",
    "Saiu",
]


class User(db.Model):
    __tablename__ = "reversa_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(
        db.String(80), unique=True, nullable=False
    )
    password = db.Column(db.Text, nullable=False)
    role = db.Column(
        db.String(20),
        nullable=False,
        default="funcionario",
        server_default="funcionario",
    )


class Equipment(db.Model):
    __tablename__ = "reversa_equipment"

    id = db.Column(db.Integer, primary_key=True)
    brand = db.Column(db.String(200), nullable=False)
    model = db.Column(db.String(200), nullable=False)
    serial = db.Column(db.Text, default="")
    mac = db.Column(db.Text, default="")
    origin = db.Column(db.Text, default="")
    notes = db.Column(db.Text, default="")
    status = db.Column(
        db.String(40), default="Recebido", nullable=False
    )
    created = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
    )
    version = db.Column(
        db.Integer, nullable=False, default=1
    )
    deleted = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        server_default=db.false(),
    )

    __mapper_args__ = {"version_id_col": version}


class Event(db.Model):
    __tablename__ = "reversa_events"

    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(
        db.Integer,
        db.ForeignKey("reversa_equipment.id"),
        nullable=False,
    )
    actor = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(40), nullable=False)
    detail = db.Column(db.Text, nullable=False)
    destination = db.Column(db.Text, default="")
    created = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
    )


with app.app_context():
    db.create_all()

    # Atualiza as tabelas existentes sem apagar os dados.
    with db.engine.begin() as connection:
        user_columns = {
            column["name"]
            for column in inspect(connection).get_columns(
                "reversa_users"
            )
        }

        if "role" not in user_columns:
            connection.execute(
                db.text(
                    "ALTER TABLE reversa_users "
                    "ADD COLUMN role VARCHAR(20) "
                    "NOT NULL DEFAULT 'funcionario'"
                )
            )

        equipment_columns = {
            column["name"]
            for column in inspect(connection).get_columns(
                "reversa_equipment"
            )
        }

        if "deleted" not in equipment_columns:
            connection.execute(
                db.text(
                    "ALTER TABLE reversa_equipment "
                    "ADD COLUMN deleted BOOLEAN "
                    "NOT NULL DEFAULT FALSE"
                )
            )

        # O login ADMIN_USERNAME torna-se administrador
        # apenas se ainda não houver administrador.
        connection.execute(
            db.text(
                "UPDATE reversa_users "
                "SET role = 'admin' "
                "WHERE username = :username "
                "AND NOT EXISTS ("
                "SELECT 1 FROM reversa_users "
                "WHERE role = 'admin'"
                ")"
            ),
            {
                "username": os.environ.get(
                    "ADMIN_USERNAME", "admin"
                ).strip()
            },
        )

    existing_user = db.session.scalar(
        db.select(User).limit(1)
    )

    if not existing_user:
        username = os.environ.get(
            "ADMIN_USERNAME", "admin"
        ).strip()
        password = os.environ.get("ADMIN_PASSWORD", "")

        if not username or len(username) > 80:
            raise RuntimeError(
                "ADMIN_USERNAME deve ter entre 1 e 80 caracteres."
            )

        if len(password) < 8:
            raise RuntimeError(
                "Defina ADMIN_PASSWORD com pelo menos 8 caracteres."
            )

        db.session.add(
            User(
                username=username,
                password=generate_password_hash(password),
                role="admin",
            )
        )
        db.session.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not getattr(g, "user", None):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user.role != "admin":
            abort(
                403,
                "Somente o administrador pode realizar esta ação.",
            )
        return view(*args, **kwargs)

    return wrapped


@app.before_request
def load_user_and_check_csrf():
    g.user = None

    if session.get("user_id"):
        g.user = db.session.get(
            User, session["user_id"]
        )

    if request.method == "POST":
        token = session.get("csrf")
        submitted_token = request.form.get("csrf", "")

        if not token or not secrets.compare_digest(
            token, submitted_token
        ):
            abort(
                400,
                "Formulário expirou. "
                "Atualize a página e tente novamente.",
            )


@app.context_processor
def context():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)

    return {
        "csrf": session["csrf"],
        "statuses": STATUSES,
        "is_admin": bool(
            getattr(g, "user", None)
            and g.user.role == "admin"
        ),
    }


@app.after_request
def headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get(
            "username", ""
        ).strip()
        password = request.form.get("password", "")

        user = db.session.scalar(
            db.select(User).where(
                User.username == username
            )
        )

        if user and check_password_hash(
            user.password, password
        ):
            session.clear()
            session.update(
                user_id=user.id,
                username=user.username,
            )
            session.permanent = True
            return redirect(url_for("index"))

        flash("Usuário ou senha incorretos.")

    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


def filtered():
    stmt = db.select(Equipment).where(
        Equipment.deleted.is_(False)
    )

    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")

    if q:
        escaped = (
            q.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        pattern = "%" + escaped + "%"

        columns = (
            Equipment.brand,
            Equipment.model,
            Equipment.serial,
            Equipment.mac,
            Equipment.origin,
        )

        stmt = stmt.where(
            or_(
                *[
                    column.ilike(pattern, escape="\\")
                    for column in columns
                ]
            )
        )

    if status in STATUSES:
        stmt = stmt.where(
            Equipment.status == status
        )

    return stmt.order_by(Equipment.id.desc())


@app.get("/")
@login_required
def index():
    counts = dict(
        db.session.execute(
            db.select(
                Equipment.status,
                db.func.count(),
            )
            .where(Equipment.deleted.is_(False))
            .group_by(Equipment.status)
        ).all()
    )

    try:
        page = max(
            1, int(request.args.get("page", 1))
        )
    except ValueError:
        page = 1

    records = db.paginate(
        filtered(),
        page=page,
        per_page=50,
        error_out=False,
    )

    return render_template(
        "index.html",
        records=records,
        counts=counts,
    )


@app.route("/novo", methods=["GET", "POST"])
@login_required
def new():
    if request.method == "POST":
        fields = [
            "brand", "model", "serial",
            "mac", "origin", "notes",
        ]

        data = {
            key: request.form.get(key, "").strip()
            for key in fields
        }

        if (
            not data["brand"]
            or not data["model"]
            or len(data["brand"]) > 200
            or len(data["model"]) > 200
        ):
            flash(
                "Informe marca e modelo "
                "com até 200 caracteres."
            )
        else:
            item = Equipment(**data)
            db.session.add(item)
            db.session.flush()

            db.session.add(
                Event(
                    equipment_id=item.id,
                    actor=g.user.username,
                    status="Recebido",
                    detail="Entrada cadastrada.",
                )
            )

            db.session.commit()
            flash("Roteador cadastrado!")

            return redirect(
                url_for("detail", item_id=item.id)
            )

    return render_template("new.html")


@app.route(
    "/equipamento/<int:item_id>",
    methods=["GET", "POST"],
)
@login_required
def detail(item_id):
    item = db.get_or_404(Equipment, item_id)

    if item.deleted:
        abort(404)

    if request.method == "POST":
        status = request.form.get("status", "")
        detail_text = request.form.get(
            "detail", ""
        ).strip()
        destination = request.form.get(
            "destination", ""
        ).strip()

        if request.form.get("version") != str(item.version):
            flash(
                "Outro registro alterou este equipamento. "
                "Confira a situação atual e tente novamente."
            )
        elif (
            status not in STATUSES
            or not detail_text
            or (status == "Saiu" and not destination)
        ):
            flash(
                "Informe a situação e o resultado/motivo. "
                "Na saída, informe também o destino."
            )
        else:
            item.status = status
            item.version += 1

            db.session.add(
                Event(
                    equipment_id=item.id,
                    actor=g.user.username,
                    status=status,
                    detail=detail_text,
                    destination=destination,
                )
            )

            try:
                db.session.commit()
                flash("Movimentação registrada!")
            except StaleDataError:
                db.session.rollback()
                flash(
                    "O equipamento foi alterado por outra pessoa. "
                    "Confira e tente novamente."
                )

        return redirect(
            url_for("detail", item_id=item.id)
        )

    events = db.session.scalars(
        db.select(Event)
        .where(Event.equipment_id == item.id)
        .order_by(Event.id.desc())
    ).all()

    return render_template(
        "detail.html",
        item=item,
        events=events,
    )


@app.route("/usuarios", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        username = request.form.get(
            "username", ""
        ).strip()
        password = request.form.get("password", "")

        if (
            not username
            or len(username) > 80
            or len(password) < 8
        ):
            flash(
                "Informe login com até 80 caracteres "
                "e senha com pelo menos 8 caracteres."
            )

        elif db.session.scalar(
            db.select(User).where(
                User.username == username
            )
        ):
            flash("Esse login já existe. Escolha outro.")

        else:
            # Novos usuários sempre são funcionários.
            db.session.add(
                User(
                    username=username,
                    password=generate_password_hash(password),
                    role="funcionario",
                )
            )

            try:
                db.session.commit()
                flash(
                    "Usuário criado! Ele pode cadastrar "
                    "e registrar testes, mas não excluir."
                )
                return redirect(url_for("users"))

            except IntegrityError:
                db.session.rollback()
                flash("Esse login já existe. Escolha outro.")

    accounts = db.session.scalars(
        db.select(User).order_by(User.id)
    ).all()

    return render_template(
        "users.html",
        accounts=accounts,
    )


@app.post("/equipamento/<int:item_id>/excluir")
@admin_required
def delete_equipment(item_id):
    item = db.get_or_404(Equipment, item_id)

    if item.deleted:
        abort(404)

    if request.form.get("confirm") != "EXCLUIR":
        flash("Digite EXCLUIR para confirmar.")
        return redirect(
            url_for("detail", item_id=item.id)
        )

    if request.form.get("version") != str(item.version):
        flash(
            "O equipamento foi alterado. "
            "Confira os dados antes de excluir."
        )
        return redirect(
            url_for("detail", item_id=item.id)
        )

    item.deleted = True
    item.version += 1

    db.session.add(
        Event(
            equipment_id=item.id,
            actor=g.user.username,
            status=item.status,
            detail=(
                "Cadastro excluído pelo administrador. "
                "Histórico preservado."
            ),
        )
    )

    try:
        db.session.commit()
        flash(
            "Equipamento excluído da lista. "
            "O histórico foi preservado."
        )
    except StaleDataError:
        db.session.rollback()
        flash(
            "O equipamento foi alterado por outra pessoa. "
            "Tente novamente."
        )

    return redirect(url_for("index"))


def csv_response(rows, filename):
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=";")

    for row in rows:
        safe_row = []

        for value in row:
            text = str(value)

            if text.lstrip().startswith(
                ("=", "+", "-", "@")
            ):
                value = "'" + text

            safe_row.append(value)

        writer.writerow(safe_row)

    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                f"attachment; filename={filename}"
        },
    )


@app.get("/exportar")
@login_required
def export():
    rows = [[
        "ID", "Marca", "Modelo", "Serial", "MAC",
        "Origem", "Situação", "Entrada UTC", "Observações",
    ]]

    for item in db.session.scalars(filtered()):
        rows.append([
            item.id,
            item.brand,
            item.model,
            item.serial,
            item.mac,
            item.origin,
            item.status,
            item.created.isoformat(),
            item.notes,
        ])

    return csv_response(rows, "roteadores.csv")


@app.get("/historico.csv")
@login_required
def history_export():
    rows = [[
        "ID equipamento", "Data UTC", "Responsável",
        "Situação", "Resultado/motivo", "Destino",
    ]]

    events = db.session.scalars(
        db.select(Event).order_by(Event.id)
    )

    for event in events:
        rows.append([
            event.equipment_id,
            event.created.isoformat(),
            event.actor,
            event.status,
            event.detail,
            event.destination,
        ])

    return csv_response(rows, "historico.csv")


@app.get("/health")
def health():
    db.session.execute(db.text("SELECT 1"))
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
    )
