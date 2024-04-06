gst-launch-1.0 udpsrc port=12345 ! image/jpeg,width=200,height=200,framerate=30/1 ! rtpjpegpay ! udpsink sync=false host=127.0.0.1 port=5600
