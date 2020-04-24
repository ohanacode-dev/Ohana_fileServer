$(document).ready(function(){
    $('#filer_input').filer({
        showThumbs: true,
        addMore: true,
        templates: {
            box: '<ul class="jFiler-items-list jFiler-items-default"></ul>',
            item: '<li class="jFiler-item"><div class="jFiler-item-container"><div class="jFiler-item-inner"><div class="jFiler-item-icon pull-left">{{fi-icon}}</div><div class="jFiler-item-info pull-left"><div class="jFiler-item-title" title="{{fi-name}}">{{fi-name | limitTo:30}}</div><div class="jFiler-item-others"><span>size: {{fi-size2}}</span><span>type: {{fi-extension}}</span><span class="jFiler-item-status">{{fi-progressBar}}</span></div></div></div></div></li>',
            itemAppend: '<li class="jFiler-item"><div class="jFiler-item-container"><div class="jFiler-item-inner"><div class="jFiler-item-icon pull-left">{{fi-icon}}</div><div class="jFiler-item-info pull-left"><div class="jFiler-item-title">{{fi-name | limitTo:35}}</div><div class="jFiler-item-others"><span>size: {{fi-size2}}</span><span>type: {{fi-extension}}</span><span class="jFiler-item-status"></span></div></div></div></div></li>',
            progressBar: '<div class="bar"></div>',
            itemAppendToEnd: false,
            removeConfirmation: true,
            canvasImage: true,
            _selectors: {
                list: '.jFiler-items-list',
                item: '.jFiler-item',
                progressBar: '.bar',
                remove: '.jFiler-item-trash-action'
            }
        },
        uploadFile: {
            url: "#",
            data: {},
            type: 'POST',
            enctype: 'multipart/form-data',
            beforeSend: function(){},
            success: function(data, el){
                    var parent = el.find(".jFiler-jProgressBar").parent();
                    var resp = JSON.parse(data);
                    if (resp.status == 'success') {
                        el.find(".jFiler-jProgressBar").fadeOut("slow", function(){
                            $("<div class=\"jFiler-item-others text-success\"><i class=\"icon-jfi-check-circle\"></i> Success</div>").hide().appendTo(parent).fadeIn("slow");
                        });
                    } else {
                        el.find(".jFiler-jProgressBar").fadeOut("slow", function(){
                            $("<div class=\"jFiler-item-others text-error\"><i class=\"icon-jfi-minus-circle\"></i> Error: " + resp.msg + "</div>").hide().appendTo(parent).fadeIn("slow");
                        });
                    }
            },
            error: function(el){
                var parent = el.find(".jFiler-jProgressBar").parent();
                el.find(".jFiler-jProgressBar").fadeOut("slow", function(){
                    $("<div class=\"jFiler-item-others text-error\"><i class=\"icon-jfi-minus-circle\"></i> Error</div>").hide().appendTo(parent).fadeIn("slow");
                });
            },
            statusCode: null,
            onProgress: null,
            onComplete: null
        },
        captions: {
            button: "Add Files",
            feedback: "Choose files To Upload",
            feedback2: "files were chosen",
            drop: "Drop file here to Upload",
            removeConfirmation: "Are you sure you want to remove this file?",
            errors: {
                filesLimit: "Only {{fi-limit}} files are allowed to be uploaded.",
                filesType: "Only Images are allowed to be uploaded.",
                filesSize: "{{fi-name}} is too large! Please upload file up to {{fi-fileMaxSize}} MB.",
                filesSizeAll: "Files you've choosed are too large! Please upload files up to {{fi-maxSize}} MB.",
                folderUpload: "You are not allowed to upload folders."
            }
        }
    });
    $('#close-uploader').click(function() {
        $('#filer_input').prop("jFiler").reset()
        location.reload(true);
    });

    var urlRootClasses = document.getElementsByClassName("url_root");
    for (var i = 0; i < urlRootClasses.length; i++) {
      urlRootClasses[i].innerHTML = window.location.host;
    }
});

var curPath = document.getElementById("dirpath").value;
var target;

function copyToClipboard(stringtext) {
    var dummy = document.createElement("input");
    document.body.appendChild(dummy);
    dummy.setAttribute("id", "dummy_id");
    dummy.value=stringtext;
    dummy.select();
    document.execCommand("copy");
    document.body.removeChild(dummy);
}

function msgBox(msg)
{
    var el = document.createElement("div");
    el.setAttribute("style","position:absolute;bottom:20px;right:20px;background:#e5e5e5;border-radius: 5px;" +
                            "border-radius:3px;box-shadow: 1px 1px 4px rgba(0,0,0,.2);padding:1em;");
    el.innerHTML = msg;
    setTimeout(
        function(){ el.parentNode.removeChild(el); },
        4000
    );
    document.body.appendChild(el);
}

function download(){
    url = target
    document.getElementById('my_iframe').src = url;
}

function queryServer(action){

    if( ((action == "del") && confirm("Really delete\n" + curPath + target)) ||
        (action != "del")){

        $.ajax({
            type: "GET",
            url: window.location.protocol + "//" + window.location.host,
            cache: false,
            data: {
                    action: action,
                    path: curPath,
                    name: target
                },
            success: function (response) {
                try {
                    var resp = JSON.parse(response);
                    if(resp.status == 0){
                        if(resp.share.length > 1){
                            var url = window.location.protocol + '//' + window.location.hostname + ':' + window.location.port + '/' + resp.share;
                            copyToClipboard(url);
                            msgBox("Copied to clipboard shareable link:<br>" + url);

                        }else{
                            location.reload(true);
                        }
                    }else{
                        console.log("Error: " + resp.error);
                    }
                }
                catch (e) {
                    //alert('Error: no communication to main function');
                }
            },
            error: function () {
                //alert('Error: Lost connection to the server:');
            }
        });
    }
}

function getFolderName(){
    var x;
    var name = prompt("Please type folder name.","");
    if (name != null){
        target = name;
        queryServer("new");
    }
}

function newRepo(){
    var x;
    var name = prompt("Name of your repository.","");
    if (name != null){
        target = name;
        queryServer("repository");
    }
}

var menu = document.querySelector('.menu');

function showMenu(x, y, itemType){
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
    menu.classList.add('show-menu');

    if(itemType == "dir"){
        document.getElementById("share-menu").style.display = "none";
        document.getElementById("archive-menu").style.display = "block";
        document.getElementById("download-menu").style.display = "none";

    }else{
        document.getElementById("share-menu").style.display = "block";
        document.getElementById("archive-menu").style.display = "none";
        document.getElementById("download-menu").style.display = "block";
    }
}

function hideMenu(){
    menu.classList.remove('show-menu');
    target = null;
}

function onContextMenu(e){
    targetParent = event.target.parentElement;
    try {
        var classes = targetParent.className.split(' ');
        if(classes[0] == "item-row"){
            e.preventDefault();
            target = targetParent.id;

            var itemType = classes[1].split("-")[0];
            showMenu(e.pageX, e.pageY, itemType);
            document.addEventListener('click', onClick, false);
        }
    }catch(err){
        //console.log(err.message);
    }
}

function onClick(e){
    hideMenu();
    document.removeEventListener('click', onClick);
}

document.addEventListener('contextmenu', onContextMenu, false);


