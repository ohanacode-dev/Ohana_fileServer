function msgBox(msg)
{
    if(msg.length > 4){
        var el = document.createElement("p");
        el.setAttribute("style","position:absolute;top:20px;left:20px;background:#e5e5e5;border-radius: 5px;" +
                                "box-shadow: 1px 1px 4px rgba(0,0,0,.2);padding:1em;width: 20em;max-width:90%;");


        el.innerHTML = msg;
        setTimeout(
            function(){ el.parentNode.removeChild(el); },
            5000
        );
        document.getElementById("msg-placeholder").appendChild(el);
    }
}

function admin_cmd(cmd){
    var passwd = document.getElementById("passw").value;

    $.ajax({
        type: "GET",
        url: window.location.protocol + "//" + window.location.host + "/admin",
        cache: false,
        data: {
                cmd: cmd,
                password: passwd
            },
        success: function (response) {
            try {
                var resp = JSON.parse(response);
                msgBox(resp.msg);
            }
            catch (e) {
//                alert('Error: no communication to main function');
            }
        },
        error: function () {
            //alert('Error: Lost connection to the server:');
        }
    });

}
window.addEventListener("load", function(){
    var server_msg =  document.getElementById("server_msg");
    if(server_msg){
        msgBox(server_msg.value);
    }
});
