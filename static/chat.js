// ---------------- SOCKET INIT ----------------
const socket = io();
const msg = document.getElementById("msg");
const chatBox = document.getElementById("chat-box");
const scrollBtn = document.getElementById("scrollDownBtn");
let typingTimer = null;
let isTyping = false;
let unreadCount = 0;

function formatTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);   // ISO → local automatically
    return d.toLocaleTimeString("en-IN", {
        hour: "2-digit",
        minute: "2-digit",
        hour12: true
    });
}




function getDateLabel(iso) {
    const d = new Date(iso);
    const now = new Date();

    const isToday =
        d.toDateString() === now.toDateString();

    const yesterday = new Date();
    yesterday.setDate(now.getDate() - 1);

    const isYesterday =
        d.toDateString() === yesterday.toDateString();

    if (isToday) return "Today";
    if (isYesterday) return "Yesterday";

    // last 7 days → weekday
    const diffDays = Math.floor(
        (now - d) / (1000 * 60 * 60 * 24)
    );

    if (diffDays < 7) {
        return d.toLocaleDateString([], { weekday: "long" });
    }

    // old → full date
    return d.toLocaleDateString([], {
        day: "2-digit",
        month: "short",
        year: "numeric"
    });
}

function renderDateDivider(label) {
    const div = document.createElement("div");
    div.className = "date-divider";
    div.innerText = label;
    chatBox.appendChild(div);
}


window.addEventListener("load", () => {
    socket.emit("mark_seen");
});

// ---------------- SEND TEXT ----------------
function sendMsg() {
    let text = msg.value.trim();
    if (!text) return;

    socket.emit("send_message", { text });
    msg.value = "";
}

// ---------------- FILE PICK ----------------
function openFile() {
    document.getElementById("fileInput").click();
}

document.getElementById("fileInput").addEventListener("change", async e => {
    let file = e.target.files[0];
    if (!file) return;

    let fd = new FormData();
    fd.append("file", file);

    let res = await fetch("/chat/upload", {
        method: "POST",
        body: fd
    });

    let data = await res.json();

    socket.emit("send_message", {
        text: "",
        file: data
    });
});

// ---------------- RENDER ----------------
let lastRenderedDate = null;

function renderMessage(data) {

    // 🔹 DATE SEPARATOR LOGIC (NEW)
    const msgDate = new Date(data.created_at).toDateString();

    if (msgDate !== lastRenderedDate) {
        renderDateDivider(getDateLabel(data.created_at));
        lastRenderedDate = msgDate;
    }

    let row = document.createElement("div");
    row.className = "msg " + (data.user === CURRENT_USER ? "me" : "other");


    // Profile picture
    let avatar = "";
    if (data.user !== CURRENT_USER) {
        if (data.profile_pic) {
            avatar = `
            <div class="avatar">
                <img src="${data.profile_pic}">
            </div>`;
        } else {
            avatar = `
            <div class="avatar">
                <span>${data.user[0].toUpperCase()}</span>
            </div>`;
        }
    }

    // Content
    let body = data.file
        ? (data.file.type.match(/png|jpg|jpeg|gif/)
            ? `<img src="${data.file.url}" class="preview">`
            : `<a href="${data.file.url}" target="_blank">${data.file.name}</a>`)
        : `<div class="text">${data.text}</div>`;

    row.innerHTML = `
        ${avatar}
            
        <div class="bubble"
             oncontextmenu="openEdit(event, this)"
             ontouchstart="holdStart(this)"
             ontouchend="holdEnd()">

            ${body}
            <div class="meta">
                <span class="time">${formatTime(data.created_at)}</span>
                ${data.edited ? `<span class="edited">edited</span>` : ""}
                ${data.user === CURRENT_USER ? `
                    <span class="tick ${data.status === 'seen' ? 'seen' : ''}">
                        ${renderTicks(data.status)}
                    </span>
                ` : ""}
            </div>
        </div>
    `;
    row.dataset.id = data.id;

    chatBox.appendChild(row);
}

let editingMsgId = null;


let holdTimer = null;

function holdStart(el) {
    holdTimer = setTimeout(() => startEdit(el), 600);
}

function holdEnd() {
    clearTimeout(holdTimer);
}

function openEdit(e, el) {
    e.preventDefault();
    startEdit(el);
}


function startEdit(bubble) {
    const row = bubble.closest(".msg");
    if (!row.classList.contains("me")) return;

    const textDiv = bubble.querySelector(".text");
    if (!textDiv) return;

    editingMsgId = row.dataset.id;

    const oldText = textDiv.innerText;
    const input = document.createElement("input");

    input.value = oldText;
    input.className = "edit-input";

    textDiv.replaceWith(input);
    input.focus();

    input.addEventListener("keydown", e => {
        if (e.key === "Enter") finishEdit(input);
        if (e.key === "Escape") cancelEdit(input, oldText);
    });
}


function finishEdit(input) {
    const newText = input.value.trim();
    if (!newText) return;

    socket.emit("edit_message", {
        id: editingMsgId,
        text: newText
    });
    const div = document.createElement("div");
    div.className = "text";
    div.innerText = newText;
    input.replaceWith(div);


    editingMsgId = null;
}

function cancelEdit(input, oldText) {
    const div = document.createElement("div");
    div.className = "text";
    div.innerText = oldText;
    input.replaceWith(div);
}


socket.on("message_edited", data => {
    const msg = document.querySelector(`[data-id="${data.id}"]`);
    if (!msg) return;

    msg.querySelector(".text").innerText = data.text;

    let meta = msg.querySelector(".meta");
    if (!meta.querySelector(".edited")) {
        const e = document.createElement("span");
        e.className = "edited";
        e.innerText = "edited";
        meta.prepend(e);
    }
});



function renderTicks(status) {
    if (status === "sent") return "✔";
    if (status === "delivered") return "✔✔";
    if (status === "seen") return "✔✔";
    return "";
}

window.addEventListener("load", () => {
    lastRenderedDate = null;
    const firstUnseen = document.querySelector(".msg.unseen");

    if (firstUnseen) {
        firstUnseen.scrollIntoView({
            behavior: "auto",
            block: "center"
        });
    } else {
        scrollToBottom(false);
    }
});


function emitTyping() {
    if (!isTyping) {
        socket.emit("typing");
        isTyping = true;
    }

    clearTimeout(typingTimer);

    typingTimer = setTimeout(() => {
        isTyping = false;
        socket.emit("stop_typing");
    }, 1500); // 1.5 sec after stop
}

socket.on("show_typing", data => {
    const typingDiv = document.getElementById("typing");
    typingDiv.innerText = `${data.user} is typing...`;
    typingDiv.style.display = "block";
});

socket.on("hide_typing", () => {
    const typingDiv = document.getElementById("typing");
    typingDiv.style.display = "none";
});


function scrollToBottom(smooth = true) {
    chatBox.scrollTo({
        top: chatBox.scrollHeight,
        behavior: smooth ? "smooth" : "auto"
    });
}


let lastScrollTop = 0;

chatBox.addEventListener("scroll", () => {
    const currentScrollTop = chatBox.scrollTop;

    const atBottom =
        chatBox.scrollHeight - chatBox.scrollTop - chatBox.clientHeight < 120;

    // user নিচের দিকে scroll করছে
    if (currentScrollTop > lastScrollTop && !atBottom) {
        scrollBtn.classList.add("show");
    }

    // user একদম নিচে পৌঁছালে button hide
    if (atBottom) {
        scrollBtn.classList.remove("show");
    }

    lastScrollTop = currentScrollTop;
});
scrollBtn.addEventListener("click", () => {
    scrollToBottom(true);
    scrollBtn.classList.remove("show");
});

socket.on("message_seen", () => {
    document.querySelectorAll(".tick").forEach(t => {
        t.classList.add("seen");
    });
});


socket.on("new_message", data => {
    console.log("NEW MESSAGE DATA =", data);
    renderMessage(data);

    const atBottom =
        chatBox.scrollHeight - chatBox.scrollTop - chatBox.clientHeight < 120;

    if (!atBottom) {
        unreadCount++;
        scrollBtn.innerText = unreadCount;
        scrollBtn.classList.add("show");
    } else {
        scrollToBottom(true);
        socket.emit("mark_seen");
    }
});


chatBox.addEventListener("scroll", () => {
    const atBottom =
        chatBox.scrollHeight - chatBox.scrollTop - chatBox.clientHeight < 120;

    if (atBottom && unreadCount > 0) {
        unreadCount = 0;
        scrollBtn.classList.remove("show");
        scrollBtn.innerText = "⩔";
        socket.emit("mark_seen");
    }
});

// 🔥 Render times after page load (for Jinja messages)
window.addEventListener("load", () => {
    document.querySelectorAll(".time[data-time]").forEach(el => {
        const iso = el.dataset.time;
        el.innerText = formatTime(iso);
    });
});
window.addEventListener("load", () => {
    document.querySelectorAll(".date-divider[data-date]").forEach(div => {
        div.innerText = getDateLabel(div.dataset.date);
    });
});
