from app import create_app
from app.extensions import db
from app.models import ScanBatchJob, ScanPortResult, ScanTargetResult, User


app = create_app()


def main() -> None:
    with app.app_context():
        operator = User.query.filter_by(username="operator").first()
        if operator is None:
            operator = User(username="operator", role="operator", is_active=True)
            operator.set_password("Operator123!")
            db.session.add(operator)
            db.session.commit()

        if ScanBatchJob.query.count() == 0:
            batch = ScanBatchJob(
                name="Seeded Internal VLAN Sweep",
                profile_key="service",
                profile_label="Service Detection",
                status="COMPLETED",
                target_input="10.10.10.5\n10.10.10.15",
                total_targets=2,
                completed_targets=2,
                failed_targets=0,
                running_targets=0,
                batch_size=10,
                host_timeout=180,
                retry_failed=1,
                created_by_id=operator.id,
            )
            db.session.add(batch)
            db.session.flush()

            host_one = ScanTargetResult(
                batch_job_id=batch.id,
                target="10.10.10.5",
                status="COMPLETED",
                host_state="up",
                open_ports_count=2,
                open_ports_summary="22/tcp, 443/tcp",
                services_summary="ssh (22), https (443)",
                os_guess="Linux 5.x",
                raw_output="Seed raw output",
                xml_output="<nmaprun />",
            )
            host_one.ports.extend(
                [
                    ScanPortResult(protocol="tcp", port=22, state="open", service="ssh"),
                    ScanPortResult(protocol="tcp", port=443, state="open", service="https"),
                ]
            )
            host_two = ScanTargetResult(
                batch_job_id=batch.id,
                target="10.10.10.15",
                status="COMPLETED",
                host_state="up",
                open_ports_count=1,
                open_ports_summary="3389/tcp",
                services_summary="ms-wbt-server (3389)",
                os_guess="Windows Server",
                raw_output="Seed raw output",
                xml_output="<nmaprun />",
            )
            host_two.ports.append(
                ScanPortResult(protocol="tcp", port=3389, state="open", service="ms-wbt-server")
            )
            db.session.add_all([host_one, host_two])
            db.session.commit()

        print("Seed data created.")


if __name__ == "__main__":
    main()
