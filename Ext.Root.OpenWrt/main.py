import re
import time
from getpass import getpass

import paramiko
from yaspin import yaspin


# Function to execute a command on the remote router
def execute_command(ssh_client, command, sudo=False, timeout=60):
    with ssh_client.invoke_shell() as shell:
        # Send command with optional sudo
        if sudo:
            command = f"sudo {command}"
        shell.send(f"{command}\n")

        # Set up buffers and timers
        output = ""
        end_time = time.time() + timeout
        prompt = "root@OpenGuard:~#"  # Adjust based on your environment's prompt

        while True:
            # Read output in chunks
            if time.time() > end_time:
                raise TimeoutError("Command execution timed out.")

            if shell.recv_ready():
                chunk = shell.recv(4096).decode()
                output += chunk

                # Check if the prompt has appeared after the command output
                if prompt in output:
                    # Look for the prompt appearing after the command output
                    if output.count(prompt) > 1:
                        output = re.findall(
                            rf"{re.escape(prompt)}(.*?){re.escape(prompt)}",
                            output,
                            re.DOTALL,
                        )
                        if len(output) > 0:
                            output = output[0]
                        break

            time.sleep(0.1)  # Sleep briefly to avoid busy-waiting

        return output


# Function to detect and list external drives
def detect_drives(ssh_client):
    output = execute_command(ssh_client, "cat /proc/mounts")
    # Example output line: /dev/sda1 / ext4 rw,relatime,data=ordered 0 0
    devices = re.findall(r"/dev/\S+", output)
    return list(set(devices))  # Remove duplicates


# Function to configure extroot
def configure_extroot(ssh_client, device):
    with yaspin(text="Preparing environment"):
        execute_command(ssh_client, "opkg update")
        execute_command(
            ssh_client,
            "opkg install block-mount kmod-fs-ext4 e2fsprogs parted kmod-usb-storage",
        )

    with yaspin(text="Partitioning and formatting disk"):
        execute_command(
            ssh_client, f"parted -s {device} -- mklabel gpt mkpart extroot 2048s -2048s"
        )
        partition = f"{device}1"
        execute_command(ssh_client, f"mkfs.ext4 -L extroot {partition}")

    with yaspin(text="Configuring extroot"):
        uuid_output = execute_command(ssh_client, f"block info {partition}")
        uuid = re.search(r'UUID="(\S*)"', uuid_output).group(1)
        mount_output = execute_command(ssh_client, "block info")
        mount = re.search(r'MOUNT="(\S*/overlay)"', mount_output).group(1)

        execute_command(ssh_client, "uci -q delete fstab.extroot")
        execute_command(ssh_client, 'uci set fstab.extroot="mount"')
        execute_command(ssh_client, f'uci set fstab.extroot.uuid="{uuid}"')
        execute_command(ssh_client, f'uci set fstab.extroot.target="{mount}"')
        execute_command(ssh_client, "uci commit fstab")

    with yaspin(text="Configuring rootfs_data"):
        orig = re.search(r'MOUNT="(\S*/overlay)"', mount_output).group(1)
        execute_command(ssh_client, "uci -q delete fstab.rwm")
        execute_command(ssh_client, 'uci set fstab.rwm="mount"')
        execute_command(ssh_client, f'uci set fstab.rwm.device="{orig}"')
        execute_command(ssh_client, 'uci set fstab.rwm.target="/rwm"')
        execute_command(ssh_client, "uci commit fstab")

    with yaspin(text="Transferring data"):
        execute_command(ssh_client, f"mount {partition} /mnt")
        execute_command(ssh_client, f"tar -C {mount} -cvf - . | tar -C /mnt -xf -")

    with yaspin(text="Applying changes and rebooting"):
        execute_command(ssh_client, "reboot")

    with yaspin(text="Preserving opkg lists"):
        execute_command(
            ssh_client,
            r'sed -i -e "/^lists_dir\s/s:/var/opkg-lists$:/usr/lib/opkg/lists:" /etc/opkg.conf',
        )
        execute_command(ssh_client, "opkg update")

    with yaspin(text="Setting up swap"):
        dir_path = re.search(
            r'target="(\S*)"',
            execute_command(ssh_client, "uci get fstab.extroot.target"),
        ).group(1)
        execute_command(
            ssh_client, f"dd if=/dev/zero of={dir_path}/swap bs=1M count=100"
        )
        execute_command(ssh_client, f"mkswap {dir_path}/swap")
        execute_command(ssh_client, "uci -q delete fstab.swap")
        execute_command(ssh_client, 'uci set fstab.swap="swap"')
        execute_command(ssh_client, f'uci set fstab.swap.device="{dir_path}/swap"')
        execute_command(ssh_client, "uci commit fstab")
        execute_command(ssh_client, "service fstab boot")
        execute_command(ssh_client, "cat /proc/swaps")


def main():
    router_address = (
        input("Enter remote router address [default: 192.168.1.1]: ") or "192.168.1.1"
    )
    username = input("Enter username [default: root]: ") or "root"
    password = getpass("Enter password: ") or "pa$$w0rd"

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(router_address, username=username, password=password)

    drives = detect_drives(ssh_client)
    if not drives:
        print("No external drives detected.")
        return

    print("Detected drives:")
    for i, drive_path in enumerate(drives):
        print(f"{i}: {drive_path}")

    drive_index = int(input("Select drive index for extroot: "))
    device = f"{drives[drive_index]}"
    print(f"Selected device: {device}")

    configure_extroot(ssh_client, device)

    ssh_client.close()


if __name__ == "__main__":
    main()
