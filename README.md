# Loki_on_Kali
Docker container to run Loki on Kali Linux / Parrot-OS. Loki is a python based infrastructure pentesting tool focussing on layer 3 protocols.

# Installation

## Image

### Build your own image

* Build the container :

```
cd Docker
sudo ./build.sh
```

### Import from github

* Import the image :

`sudo docker pull ghcr.io/raizo62/loki_on_kali:latest`

* Rename the image to use the launchers

`sudo docker image tag ghcr.io/raizo62/loki_on_kali loki_on_kali`

* Delete the old name of the image

`sudo docker rmi ghcr.io/raizo62/loki_on_kali`

## Launchers

* Copy launchers in /usr/local/sbin :

```
chmod u+x Docker/run_loki_*.sh
sudo cp Docker/run_loki_*.sh /usr/local/sbin
```

# Play
```
sudo run_loki_gtk.sh
```
or
```
sudo run_loki_urw.sh
```
or
```
sudo run_loki_bash.sh
# To run loki, use the command "loki_gtk.py"
```
