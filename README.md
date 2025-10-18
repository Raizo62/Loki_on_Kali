# Loki_on_Kali
Docker container to run Loki on Kali Linux / Parrot-OS. Loki is a python based infrastructure pentesting tool focussing on layer 3 protocols.

![Gui of loki](./screenshots/Loki_gui_2023-03-12.png)

# Installation

## Image

### Method 1 : Build your own image

* Build the container :

```
cd Docker
sudo sh ./build.sh
```

### Method 2 : Import from github

* Import the image :

`sudo docker pull ghcr.io/raizo62/loki_on_kali:latest`

* Rename the image to use the launchers

`sudo docker image tag ghcr.io/raizo62/loki_on_kali loki_on_kali`

* Delete the old name of the image

`sudo docker rmi ghcr.io/raizo62/loki_on_kali`

### Method 3 : Download the file of the image

* Get the compressed image :

`wget https://github.com/Raizo62/Loki_on_Kali/releases/download/v3/loki_on_kali_image_v3.docker.tgz`

* Unzip the file :

```
tar xvf loki_on_kali_image_v3.docker.tgz
rm loki_on_kali_image_v3.docker.tgz
```

* Import the image :

`sudo docker load --input=loki_on_kali_image_v3.docker`

* Delete the unnecessary docker file :

`rm loki_on_kali_image_v3.docker`

## Launchers

* Copy launchers in /usr/local/sbin :

```
chmod u+x Docker/run_loki_*.sh
sudo cp Docker/run_loki_*.sh /usr/local/sbin
```

# Play

* Start Loki :

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

* The shared folder between Loki and the Host is '/tmp'

# Network config of Loki by GUI

## Step 1: Access Advanced Interface Configuration

1. Click on **"Network"**.
2. Click on **"Advanced Interface Config"**.

## Step 2: Create and Configure the Bridge (br23)

1. In the **"Bridge Config"** tab:
    * Click **"Add"**.
        * This creates a bridge named **"br23"**.
    * Set the **IP address** (**"Address"**) and **netmask** (**"Netmask"**) for the bridge.

## Step 3: Add a Network Interface to the Bridge

1. Select the line with the **"br23"** bridge.
2. Click **"Add"**.
    * Select the network interface (e.g., **"eth0"**) of Loki.
    * Click **"OK"**.

## Step 4: Apply and Exit Configuration

1. Click **"Run"**.
2. Click **"Cancel"** (to close the Bridge Config window).
3. Click **"Cancel"** (to close the Advanced Interface Config window).

## Step 5: Finalize Network Interface Selection

1. Click on **"Network"** again.
2. Select the **"br23"** interface.
3. Click **"OK"**.
