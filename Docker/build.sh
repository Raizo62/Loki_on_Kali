docker build -t loki_on_kali .

# chmod u+x run_loki_*.sh

# echo "* Export the image"
# docker save -o loki_on_kali_image_v2.docker loki_on_kali:latest
# echo "* Compress the exported image"
# tar cvfz loki_on_kali_image_v2.docker.tgz loki_on_kali_image_v2.docker
