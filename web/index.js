const socket = io();

socket.on('connect', function() {
    console.log('Connected to server!');
})

socket.on('infoUpdate', function(data) {
    console.log(data);
})