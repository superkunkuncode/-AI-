import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import hashlib
import os
import datetime
from PIL import Image, ImageTk
import shutil
import logging

# ====================== 数据库初始化 ======================
def init_db():
    conn = sqlite3.connect('system.db')
    c = conn.cursor()
    
    # 用户表（含权限和个人信息）
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('creator', 'admin', 'user')),
                phone TEXT DEFAULT '',
                avatar_path TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    
    # 活动表
    c.execute('''CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                start_time DATETIME NOT NULL,
                end_time DATETIME,
                status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
                created_by INTEGER REFERENCES users(id),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    
    # 操作日志表
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL,
                target_user INTEGER REFERENCES users(id),
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    
    # 创建初始账号
    initial_users = [
        ('super_creator', 'creator123', 'creator', '13800138000', ''),
        ('admin', 'admin123', 'admin', '', ''),
        ('user1', 'user123', 'user', '', '')
    ]
    
    for username, password, role, phone, avatar in initial_users:
        hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
        c.execute('''INSERT OR IGNORE INTO users (username, password, role, phone)
                    VALUES (?, ?, ?, ?)''', 
                (username, hashed_pwd, role, phone))
    
    conn.commit()
    conn.close()

# ====================== 工具函数 ======================
def hash_password(password):
    """SHA256加密密码"""
    return hashlib.sha256(password.encode()).hexdigest()

def log_action(user_id, action, target_user=None):
    """记录操作日志"""
    conn = sqlite3.connect('system.db')
    conn.execute('''INSERT INTO audit_log (user_id, action, target_user)
                 VALUES (?, ?, ?)''', 
                (user_id, action, target_user))
    conn.commit()
    conn.close()

# ====================== 主应用类 ======================
class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("综合管理系统")
        self.geometry("1000x700")
        self.current_user = None
        self.current_role = None
        
        # 创建头像缓存目录
        self.avatar_cache = os.path.join(os.getcwd(), "avatar_cache")
        os.makedirs(self.avatar_cache, exist_ok=True)
        
        # 初始化数据库
        init_db()
        
        # 创建框架容器
        self.frames = {}
        for F in (LoginFrame, GuestCenterFrame, AccountMgrFrame, ProfileFrame, ActivityMgrFrame):
            frame = F(self, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        # 显示登录界面
        self.show_frame(LoginFrame)
        self.center_window()

    def center_window(self):
        """居中显示窗口"""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def show_frame(self, frame_class):
        """切换显示框架"""
        frame = self.frames[frame_class]
        frame.tkraise()
        
        # 每次显示时刷新数据
        if hasattr(frame, 'on_show'):
            frame.on_show()
    
    def login(self, user_id, username, role):
        """用户登录处理"""
        self.current_user = user_id
        self.current_role = role
        self.show_frame(GuestCenterFrame)
        log_action(user_id, "LOGIN")

# ====================== 登录界面 ======================
class LoginFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        # 界面设计
        style = ttk.Style()
        style.configure("Login.TLabel", font=("Arial", 12))
        style.configure("Login.TEntry", font=("Arial", 12))
        
        main_frame = ttk.Frame(self)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)
        
        ttk.Label(main_frame, text="综合管理系统", font=("Arial", 24, "bold")).pack(pady=20)
        
        form_frame = ttk.Frame(main_frame)
        form_frame.pack(pady=20)
        
        # 用户名
        ttk.Label(form_frame, text="用户名:", style="Login.TLabel").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.username_entry = ttk.Entry(form_frame, width=30, style="Login.TEntry")
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)
        
        # 密码
        ttk.Label(form_frame, text="密码:", style="Login.TLabel").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.password_entry = ttk.Entry(form_frame, width=30, show="*", style="Login.TEntry")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)
        
        # 密码显示切换
        self.show_password = tk.BooleanVar(value=False)
        ttk.Checkbutton(form_frame, text="显示密码", variable=self.show_password, 
                        command=self.toggle_password).grid(row=1, column=2, padx=10, pady=10)
        
        # 登录按钮
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="登录", width=15, command=self.validate_login).pack(pady=10)
        
        # 状态栏
        self.status_bar = ttk.Label(main_frame, text="就绪", foreground="gray")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
        
        # 绑定回车键
        self.password_entry.bind("<Return>", lambda event: self.validate_login())
    
    def toggle_password(self):
        """切换密码显示状态"""
        show = self.show_password.get()
        self.password_entry.config(show="" if show else "*")
    
    def validate_login(self):
        """验证用户登录"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.status_bar.config(text="用户名和密码不能为空", foreground="red")
            return
        
        conn = sqlite3.connect('system.db')
        cursor = conn.cursor()
        
        try:
            # 获取用户信息
            cursor.execute("SELECT id, password, role FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
            
            if not user:
                self.status_bar.config(text="用户不存在", foreground="red")
                return
                
            user_id, stored_hash, role = user
            input_hash = hash_password(password)
            
            if input_hash != stored_hash:
                self.status_bar.config(text="密码错误", foreground="red")
                return
                
            # 登录成功
            self.status_bar.config(text="登录成功，正在加载...", foreground="green")
            self.update()
            self.controller.login(user_id, username, role)
            
        except Exception as e:
            self.status_bar.config(text=f"登录错误: {str(e)}", foreground="red")
        finally:
            conn.close()

# ====================== 游客中心 ======================
class GuestCenterFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        # 顶部菜单栏
        menu_frame = ttk.Frame(self)
        menu_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(menu_frame, text="游客中心", command=self.switch_to_guest).pack(side=tk.LEFT, padx=5)
        ttk.Button(menu_frame, text="账号管理", command=self.switch_to_account).pack(side=tk.LEFT, padx=5)
        ttk.Button(menu_frame, text="个人中心", command=self.switch_to_profile).pack(side=tk.LEFT, padx=5)
        
        if controller.current_role in ("creator", "admin"):
            ttk.Button(menu_frame, text="活动管理", command=self.switch_to_activity).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(menu_frame, text="退出", command=self.logout).pack(side=tk.RIGHT, padx=5)
        
        # 主内容区
        self.content_frame = ttk.Frame(self)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 显示欢迎信息
        self.show_welcome()
    
    def switch_to_guest(self):
        self.show_welcome()
    
    def switch_to_account(self):
        self.controller.show_frame(AccountMgrFrame)
    
    def switch_to_profile(self):
        self.controller.show_frame(ProfileFrame)
    
    def switch_to_activity(self):
        self.controller.show_frame(ActivityMgrFrame)
    
    def logout(self):
        log_action(self.controller.current_user, "LOGOUT")
        self.controller.current_user = None
        self.controller.current_role = None
        self.controller.show_frame(LoginFrame)
    
    def show_welcome(self):
        """显示欢迎界面和活动列表"""
        # 清除现有内容
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # 欢迎标题
        ttk.Label(self.content_frame, text="游客中心", font=("Arial", 20, "bold")).pack(pady=20)
        
        # 活动列表
        activities_frame = ttk.LabelFrame(self.content_frame, text="近期活动")
        activities_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建带滚动条的表格
        tree_frame = ttk.Frame(activities_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.activity_tree = ttk.Treeview(tree_frame, columns=("ID", "活动名称", "开始时间", "状态"), 
                                        show="headings", yscrollcommand=scrollbar.set)
        
        # 设置列宽
        self.activity_tree.column("ID", width=50, anchor=tk.CENTER)
        self.activity_tree.column("活动名称", width=200)
        self.activity_tree.column("开始时间", width=150)
        self.activity_tree.column("状态", width=100, anchor=tk.CENTER)
        
        # 设置表头
        self.activity_tree.heading("ID", text="ID")
        self.activity_tree.heading("活动名称", text="活动名称")
        self.activity_tree.heading("开始时间", text="开始时间")
        self.activity_tree.heading("状态", text="状态")
        
        self.activity_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.activity_tree.yview)
        
        # 加载活动数据
        self.load_activities()
    
    def load_activities(self):
        """从数据库加载活动数据"""
        self.activity_tree.delete(*self.activity_tree.get_children())
        
        conn = sqlite3.connect('system.db')
        cursor = conn.cursor()
        
        # 获取当前用户角色
        role = self.controller.current_role
        
        # 根据权限过滤活动
        if role in ("creator", "admin"):
            cursor.execute("SELECT id, title, start_time, status FROM activities ORDER BY start_time DESC")
        else:
            cursor.execute("SELECT id, title, start_time, status FROM activities WHERE status='approved' ORDER BY start_time DESC")
        
        activities = cursor.fetchall()
        conn.close()
        
        for activity in activities:
            # 格式化时间
            start_time = datetime.datetime.strptime(activity[2], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
            self.activity_tree.insert("", "end", values=(activity[0], activity[1], start_time, activity[3]))
        
        if not activities:
            self.activity_tree.insert("", "end", values=("", "暂无活动数据", "", ""))

# ====================== 账号管理 ======================
class AccountMgrFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.selected_user = None
        
        # 顶部菜单栏（同游客中心）
        menu_frame = ttk.Frame(self)
        menu_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(menu_frame, text="游客中心", command=lambda: controller.show_frame(GuestCenterFrame)).pack(side=tk.LEFT, padx=5)
        ttk.Button(menu_frame, text="账号管理", command=self.on_show).pack(side=tk.LEFT, padx=5)
        ttk.Button(menu_frame, text="个人中心", command=lambda: controller.show_frame(ProfileFrame)).pack(side=tk.LEFT, padx=5)
        
        if controller.current_role in ("creator", "admin"):
            ttk.Button(menu_frame, text="活动管理", command=lambda: controller.show_frame(ActivityMgrFrame)).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(menu_frame, text="退出", command=self.logout).pack(side=tk.RIGHT, padx=5)
        
        # 主内容区
        content_frame = ttk.Frame(self)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        ttk.Label(content_frame, text="账号管理系统", font=("Arial", 20, "bold")).pack(pady=10)
        
        # 用户表格
        tree_frame = ttk.LabelFrame(content_frame, text="用户列表")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建带滚动条的表格
        table_frame = ttk.Frame(tree_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = ttk.Scrollbar(table_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.user_tree = ttk.Treeview(table_frame, columns=("ID", "用户名", "角色", "注册时间"), 
                                    show="headings", yscrollcommand=scrollbar.set)
        
        # 设置列宽
        self.user_tree.column("ID", width=50, anchor=tk.CENTER)
        self.user_tree.column("用户名", width=150)
        self.user_tree.column("角色", width=100, anchor=tk.CENTER)
        self.user_tree.column("注册时间", width=180)
        
        # 设置表头
        self.user_tree.heading("ID", text="ID")
        self.user_tree.heading("用户名", text="用户名")
        self.user_tree.heading("角色", text="角色")
        self.user_tree.heading("注册时间", text="注册时间")
        
        self.user_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.user_tree.yview)
        
        # 绑定选择事件
        self.user_tree.bind("<<TreeviewSelect>>", self.on_user_select)
        
        # 操作按钮
        btn_frame = ttk.Frame(content_frame)
        btn_frame.pack(pady=10)
        
        self.change_role_btn = ttk.Button(btn_frame, text="修改角色", state=tk.DISABLED, command=self.change_role)
        self.change_role_btn.pack(side=tk.LEFT, padx=5)
        
        self.delete_user_btn = ttk.Button(btn_frame, text="删除用户", state=tk.DISABLED, command=self.delete_user)
        self.delete_user_btn.pack(side=tk.LEFT, padx=5)
        
        self.reset_pwd_btn = ttk.Button(btn_frame, text="重置密码", state=tk.DISABLED, command=self.reset_password)
        self.reset_pwd_btn.pack(side=tk.LEFT, padx=5)
        
        # 状态栏
        self.status_bar = ttk.Label(content_frame, text="选择用户进行操作", foreground="gray")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
    
    def on_show(self):
        """当框架显示时刷新数据"""
        self.load_users()
        self.selected_user = None
        self.change_role_btn.config(state=tk.DISABLED)
        self.delete_user_btn.config(state=tk.DISABLED)
        self.reset_pwd_btn.config(state=tk.DISABLED)
        self.status_bar.config(text="选择用户进行操作")
    
    def load_users(self):
        """从数据库加载用户数据"""
        self.user_tree.delete(*self.user_tree.get_children())
        
        conn = sqlite3.connect('system.db')
        cursor = conn.cursor()
        
        # 根据当前用户权限过滤
        if self.controller.current_role == "creator":
            cursor.execute("SELECT id, username, role, created_at FROM users ORDER BY id")
        else:  # admin只能管理普通用户
            cursor.execute("SELECT id, username, role, created_at FROM users WHERE role='user' ORDER BY id")
        
        users = cursor.fetchall()
        conn.close()
        
        for user in users:
            # 格式化时间
            created_at = datetime.datetime.strptime(user[3], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
            self.user_tree.insert("", "end", values=(user[0], user[1], user[2], created_at))
    
    def on_user_select(self, event):
        """处理用户选择事件"""
        selected = self.user_tree.selection()
        if not selected:
            return
            
        self.selected_user = self.user_tree.item(selected[0])["values"][0]
        self.status_bar.config(text=f"已选择用户: {self.user_tree.item(selected[0])['values'][1]}")
        
        # 根据权限启用按钮
        current_user_id = self.controller.current_user
        selected_role = self.user_tree.item(selected[0])["values"][2]
        
        # 不能操作自己
        if int(self.selected_user) == int(current_user_id):
            self.change_role_btn.config(state=tk.DISABLED)
            self.delete_user_btn.config(state=tk.DISABLED)
            self.reset_pwd_btn.config(state=tk.DISABLED)
            return
        
        # 创作者可以操作所有用户
        if self.controller.current_role == "creator":
            self.change_role_btn.config(state=tk.NORMAL)
            self.delete_user_btn.config(state=tk.NORMAL)
            self.reset_pwd_btn.config(state=tk.NORMAL)
        # 管理员只能操作普通用户
        elif self.controller.current_role == "admin" and selected_role == "user":
            self.change_role_btn.config(state=tk.NORMAL)
            self.delete_user_btn.config(state=tk.NORMAL)
            self.reset_pwd_btn.config(state=tk.NORMAL)
        else:
            self.change_role_btn.config(state=tk.DISABLED)
            self.delete_user_btn.config(state=tk.DISABLED)
            self.reset_pwd_btn.config(state=tk.DISABLED)
    
    def change_role(self):
        """修改用户角色"""
        if not self.selected_user:
            return
            
        # 创建角色选择对话框
        dialog = tk.Toplevel(self)
        dialog.title("修改用户角色")
        dialog.geometry("300x200")
        dialog.transient(self)
        dialog.grab_set()
        
        ttk.Label(dialog, text="选择新角色:").pack(pady=10)
        
        role_var = tk.StringVar(value="user")
        roles = [("普通用户", "user"), ("管理员", "admin")]
        
        if self.controller.current_role == "creator":
            roles.append(("创作者", "creator"))
        
        for text, value in roles:
            ttk.Radiobutton(dialog, text=text, variable=role_var, value=value).pack(anchor=tk.W, padx=20)
        
        def apply_change():
            new_role = role_var.get()
            conn = sqlite3.connect('system.db')
            conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, self.selected_user))
            conn.commit()
            conn.close()
            
            # 记录操作日志
            log_action(self.controller.current_user, "CHANGE_ROLE", self.selected_user)
            
            dialog.destroy()
            self.load_users()
            self.status_bar.config(text=f"已修改用户角色为: {new_role}", foreground="green")
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="确认", command=apply_change).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
    
    def delete_user(self):
        """删除用户"""
        if not self.selected_user or not messagebox.askyesno("确认", "确定要删除此用户吗？"):
            return
            
        conn = sqlite3.connect('system.db')
        conn.execute("DELETE FROM users WHERE id=?", (self.selected_user,))
        conn.commit()
        conn.close()
        
        # 记录操作日志
        log_action(self.controller.current_user, "DELETE_USER", self.selected_user)
        
        self.load_users()
        self.status_bar.config(text="用户已删除", foreground="green")
    
    def reset_password(self):
        """重置用户密码"""
        if not self.selected_user:
            return
            
        # 创建密码输入对话框
        dialog = tk.Toplevel(self)
        dialog.title("重置密码")
        dialog.geometry("300x150")
        dialog.transient(self)
        dialog.grab_set()
        
        ttk.Label(dialog, text="输入新密码:").pack(pady=(20, 5))
        
        password_entry = ttk.Entry(dialog, show="*")
        password_entry.pack(pady=5, padx=20, fill=tk.X)
        
        ttk.Label(dialog, text="确认新密码:").pack(pady=5)
        
        confirm_entry = ttk.Entry(dialog, show="*")
        confirm_entry.pack(pady=5, padx=20, fill=tk.X)
        
        status_label = ttk.Label(dialog, text="", foreground="red")
        status_label.pack(pady=5)
        
        def apply_reset():
            password = password_entry.get()
            confirm = confirm_entry.get()
            
            if not password:
                status_label.config(text="密码不能为空")
                return
                
            if password != confirm:
                status_label.config(text="两次输入的密码不一致")
                return
                
            hashed_pwd = hash_password(password)
            
            conn = sqlite3.connect('system.db')
            conn.execute("UPDATE users SET password=? WHERE id=?", (hashed_pwd, self.selected_user))
            conn.commit()
            conn.close()
            
            # 记录操作日志
            log_action(self.controller.current_user, "RESET_PASSWORD", self.selected_user)
            
            dialog.destroy()
            self.status_bar.config(text="密码已重置", foreground="green")
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="确认", command=apply_reset).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
    
    def logout(self):
        log_action(self.controller.current_user, "LOGOUT")
        self.controller.current_user = None
        self.controller.current_role = None
        self.controller.show_frame(LoginFrame)

# ====================== 个人中心 ======================
class ProfileFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.avatar_path = ""
        self.avatar_img = None
        
        # 顶部菜单栏（同游客中心）
        menu_frame = ttk.Frame(self)
        menu_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(menu_frame, text="游客中心", command=lambda: controller.show_frame(GuestCenterFrame)).pack(side=tk.LEFT, padx=5)
        ttk.Button(menu_frame, text="账号管理", command=lambda: controller.show_frame(AccountMgrFrame)).pack(side=tk.LEFT, padx=5)
        ttk.Button(menu_frame, text="个人中心", command=self.on_show).pack(side=tk.LEFT, padx=5)
        
        if controller.current_role in ("creator", "admin"):
            ttk.Button(menu_frame, text="活动管理", command=lambda: controller.show_frame(ActivityMgrFrame)).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(menu_frame, text="退出", command=self.logout).pack(side=tk.RIGHT, padx=5)
        
        # 主内容区
        content_frame = ttk.Frame(self)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        ttk.Label(content_frame, text="个人中心", font=("Arial", 20, "bold")).pack(pady=10)
        
        # 头像区域
        avatar_frame = ttk.Frame(content_frame)
        avatar_frame.pack(pady=20)
        
        self.avatar_label = ttk.Label(avatar_frame)
        self.avatar_label.pack(side=tk.LEFT, padx=20)
        
        ttk.Button(avatar_frame, text="更换头像", command=self.change_avatar).pack(side=tk.LEFT, padx=10)
        
        # 表单区域
        form_frame = ttk.Frame(content_frame)
        form_frame.pack(fill=tk.X, padx=50, pady=10)
        
        # 用户名
        ttk.Label(form_frame, text="用户名:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.username_var = tk.StringVar()
        ttk.Label(form_frame, textvariable=self.username_var).grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        # 角色
        ttk.Label(form_frame, text="角色:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.role_var = tk.StringVar()
        ttk.Label(form_frame, textvariable=self.role_var).grid(row=1, column=1, padx=10, pady=10, sticky="w")
        
        # 手机号
        ttk.Label(form_frame, text="手机号:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.phone_entry = ttk.Entry(form_frame, width=30)
        self.phone_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")
        
        # 密码修改
        ttk.Label(form_frame, text="修改密码:").grid(row=3, column=0, padx=10, pady=10, sticky="e")
        
        pwd_frame = ttk.Frame(form_frame)
        pwd_frame.grid(row=3, column=1, padx=10, pady=10, sticky="w")
        
        ttk.Label(pwd_frame, text="旧密码:").pack(side=tk.LEFT, padx=5)
        self.old_pwd_entry = ttk.Entry(pwd_frame, width=15, show="*")
        self.old_pwd_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(pwd_frame, text="新密码:").pack(side=tk.LEFT, padx=5)
        self.new_pwd_entry = ttk.Entry(pwd_frame, width=15, show="*")
        self.new_pwd_entry.pack(side=tk.LEFT, padx=5)
        
        # 按钮区域
        btn_frame = ttk.Frame(content_frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="保存信息", command=self.save_profile).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="修改密码", command=self.change_password).pack(side=tk.LEFT, padx=10)
        
        # 状态栏
        self.status_bar = ttk.Label(content_frame, text="", foreground="green")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
    
    def on_show(self):
        """当框架显示时加载用户数据"""
        conn = sqlite3.connect('system.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, role, phone, avatar_path FROM users WHERE id=?", 
                      (self.controller.current_user,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            self.username_var.set(user[0])
            self.role_var.set(user[1])
            self.phone_entry.delete(0, tk.END)
            self.phone_entry.insert(0, user[2] if user[2] else "")
            self.avatar_path = user[3] if user[3] else ""
            
            # 加载头像
            self.load_avatar()
        
        # 清空密码字段
        self.old_pwd_entry.delete(0, tk.END)
        self.new_pwd_entry.delete(0, tk.END)
        self.status_bar.config(text="")
    
    def load_avatar(self):
        """加载用户头像"""
        if not self.avatar_path or not os.path.exists(self.avatar_path):
            # 使用默认头像
            self.avatar_img = None
            self.avatar_label.config(image=None, text="无头像")
            return
        
        try:
            # 创建头像缓存
            cache_path = os.path.join(self.controller.avatar_cache, 
                                    os.path.basename(self.avatar_path))
            
            if not os.path.exists(cache_path):
                shutil.copy(self.avatar_path, cache_path)
            
            # 加载并调整大小
            img = Image.open(cache_path)
            img = img.resize((100, 100), Image.LANCZOS)
            self.avatar_img = ImageTk.PhotoImage(img)
            self.avatar_label.config(image=self.avatar_img)
        except Exception as e:
            self.avatar_label.config(image=None, text="头像加载失败")
    
    def change_avatar(self):
        """更换用户头像"""
        file_path = filedialog.askopenfilename(
            title="选择头像",
            filetypes=[("图像文件", "*.jpg *.jpeg *.png")]
        )
        
        if not file_path:
            return
            
        # 验证文件类型
        if not file_path.lower().endswith(('.png', '.jpg', '.jpeg')):
            messagebox.showerror("错误", "只支持 JPG/PNG 格式的图片")
            return
        
        # 更新头像
        self.avatar_path = file_path
        self.load_avatar()
        self.status_bar.config(text="头像已更新，请保存信息", foreground="blue")
    
    def save_profile(self):
        """保存个人信息"""
        phone = self.phone_entry.get()
        
        conn = sqlite3.connect('system.db')
        conn.execute("UPDATE users SET phone=?, avatar_path=? WHERE id=?", 
                    (phone, self.avatar_path, self.controller.current_user))
        conn.commit()
        conn.close()
        
        self.status_bar.config(text="个人信息已保存", foreground="green")
    
    def change_password(self):
        """修改密码"""
        old_pwd = self.old_pwd_entry.get()
        new_pwd = self.new_pwd_entry.get()
        
        if not old_pwd or not new_pwd:
            self.status_bar.config(text="密码不能为空", foreground="red")
            return
            
        conn = sqlite3.connect('system.db')
        cursor = conn.cursor()
        
        # 验证旧密码
        cursor.execute("SELECT password FROM users WHERE id=?", (self.controller.current_user,))
        stored_hash = cursor.fetchone()[0]
        
        if hash_password(old_pwd) != stored_hash:
            self.status_bar.config(text="旧密码错误", foreground="red")
            conn.close()
            return
            
        # 更新密码
        new_hash = hash_password(new_pwd)
        conn.execute("UPDATE users SET password=? WHERE id=?", 
                   (new_hash, self.controller.current_user))
        conn.commit()
        conn.close()
        
        # 清空密码字段
        self.old_pwd_entry.delete(0, tk.END)
        self.new_pwd_entry.delete(0, tk.END)
        
        self.status_bar.config(text="密码修改成功", foreground="green")
        log_action(self.controller.current_user, "CHANGE_PASSWORD")
    
    def logout(self):
        log_action(self.controller.current_user, "LOGOUT")
        self.controller.current_user = None
        self.controller.current_role = None
        self.controller.show_frame(LoginFrame)

# ====================== 活动管理 ======================
class ActivityMgrFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.selected_activity = None
        
        # 顶部菜单栏（同游客中心）
        menu_frame = ttk.Frame(self)
        menu_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(menu_frame, text="游客中心", command=lambda: controller.show_frame(GuestCenterFrame)).pack(side=tk.LEFT, padx=5)
        ttk.Button(menu_frame, text="账号管理", command=lambda: controller.show_frame(AccountMgrFrame)).pack(side=tk.LEFT, padx=5)
        ttk.Button(menu_frame, text="个人中心", command=lambda: controller.show_frame(ProfileFrame)).pack(side=tk.LEFT, padx=5)
        ttk.Button(menu_frame, text="活动管理", command=self.on_show).pack(side=tk.LEFT, padx=5)
        ttk.Button(menu_frame, text="退出", command=self.logout).pack(side=tk.RIGHT, padx=5)
        
        # 主内容区
        content_frame = ttk.Frame(self)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        ttk.Label(content_frame, text="活动管理系统", font=("Arial", 20, "bold")).pack(pady=10)
        
        # 活动表格
        tree_frame = ttk.LabelFrame(content_frame, text="活动列表")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建带滚动条的表格
        table_frame = ttk.Frame(tree_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scrollbar = ttk.Scrollbar(table_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.activity_tree = ttk.Treeview(table_frame, columns=("ID", "活动名称", "开始时间", "状态", "创建人"), 
                                        show="headings", yscrollcommand=scrollbar.set)
        
        # 设置列宽
        self.activity_tree.column("ID", width=50, anchor=tk.CENTER)
        self.activity_tree.column("活动名称", width=200)
        self.activity_tree.column("开始时间", width=150)
        self.activity_tree.column("状态", width=100, anchor=tk.CENTER)
        self.activity_tree.column("创建人", width=150)
        
        # 设置表头
        self.activity_tree.heading("ID", text="ID")
        self.activity_tree.heading("活动名称", text="活动名称")
        self.activity_tree.heading("开始时间", text="开始时间")
        self.activity_tree.heading("状态", text="状态")
        self.activity_tree.heading("创建人", text="创建人")
        
        self.activity_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.activity_tree.yview)
        
        # 绑定选择事件
        self.activity_tree.bind("<<TreeviewSelect>>", self.on_activity_select)
        
        # 操作按钮
        btn_frame = ttk.Frame(content_frame)
        btn_frame.pack(pady=10)
        
        self.create_btn = ttk.Button(btn_frame, text="创建活动", command=self.create_activity)
        self.create_btn.pack(side=tk.LEFT, padx=5)
        
        self.edit_btn = ttk.Button(btn_frame, text="编辑活动", state=tk.DISABLED, command=self.edit_activity)
        self.edit_btn.pack(side=tk.LEFT, padx=5)
        
        self.approve_btn = ttk.Button(btn_frame, text="审核通过", state=tk.DISABLED, command=lambda: self.change_status('approved'))
        self.approve_btn.pack(side=tk.LEFT, padx=5)
        
        self.reject_btn = ttk.Button(btn_frame, text="审核拒绝", state=tk.DISABLED, command=lambda: self.change_status('rejected'))
        self.reject_btn.pack(side=tk.LEFT, padx=5)
        
        self.delete_btn = ttk.Button(btn_frame, text="删除活动", state=tk.DISABLED, command=self.delete_activity)
        self.delete_btn.pack(side=tk.LEFT, padx=5)
        
        # 状态栏
        self.status_bar = ttk.Label(content_frame, text="选择活动进行操作", foreground="gray")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
    
    def on_show(self):
        """当框架显示时刷新数据"""
        self.load_activities()
        self.selected_activity = None
        self.edit_btn.config(state=tk.DISABLED)
        self.approve_btn.config(state=tk.DISABLED)
        self.reject_btn.config(state=tk.DISABLED)
        self.delete_btn.config(state=tk.DISABLED)
        self.status_bar.config(text="选择活动进行操作")
    
    def load_activities(self):
        """从数据库加载活动数据"""
        self.activity_tree.delete(*self.activity_tree.get_children())
        
        conn = sqlite3.connect('system.db')
        cursor = conn.cursor()
        
        # 根据当前用户权限过滤
        if self.controller.current_role == "creator":
            cursor.execute('''SELECT a.id, a.title, a.start_time, a.status, u.username 
                          FROM activities a
                          JOIN users u ON a.created_by = u.id
                          ORDER BY a.start_time DESC''')
        else:  # admin只能看到自己创建和待审核的活动
            cursor.execute('''SELECT a.id, a.title, a.start_time, a.status, u.username 
                          FROM activities a
                          JOIN users u ON a.created_by = u.id
                          WHERE a.created_by = ? OR a.status = 'pending'
                          ORDER BY a.start_time DESC''', 
                          (self.controller.current_user,))
        
        activities = cursor.fetchall()
        conn.close()
        
        for activity in activities:
            # 格式化时间
            start_time = datetime.datetime.strptime(activity[2], "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M")
            self.activity_tree.insert("", "end", values=(activity[0], activity[1], start_time, activity[3], activity[4]))
        
        if not activities:
            self.activity_tree.insert("", "end", values=("", "暂无活动数据", "", "", ""))
    
    def on_activity_select(self, event):
        """处理活动选择事件"""
        selected = self.activity_tree.selection()
        if not selected:
            return
            
        self.selected_activity = self.activity_tree.item(selected[0])["values"][0]
        activity_status = self.activity_tree.item(selected[0])["values"][3]
        creator = self.activity_tree.item(selected[0])["values"][4]
        
        self.status_bar.config(text=f"已选择活动: {self.activity_tree.item(selected[0])['values'][1]}")
        
        # 根据权限启用按钮
        current_user_id = self.controller.current_user
        
        # 创作者可以操作所有活动
        if self.controller.current_role == "creator":
            self.edit_btn.config(state=tk.NORMAL)
            self.delete_btn.config(state=tk.NORMAL)
            
            # 审核按钮状态
            if activity_status == "pending":
                self.approve_btn.config(state=tk.NORMAL)
                self.reject_btn.config(state=tk.NORMAL)
            else:
                self.approve_btn.config(state=tk.DISABLED)
                self.reject_btn.config(state=tk.DISABLED)
        # 管理员只能操作自己创建的活动和待审核的活动
        elif self.controller.current_role == "admin":
            # 编辑和删除只能操作自己创建的活动
            if creator == self.controller.username_var:
                self.edit_btn.config(state=tk.NORMAL)
                self.delete_btn.config(state=tk.NORMAL)
            else:
                self.edit_btn.config(state=tk.DISABLED)
                self.delete_btn.config(state=tk.DISABLED)
            
            # 审核按钮状态（只能审核待审核活动）
            if activity_status == "pending":
                self.approve_btn.config(state=tk.NORMAL)
                self.reject_btn.config(state=tk.NORMAL)
            else:
                self.approve_btn.config(state=tk.DISABLED)
                self.reject_btn.config(state=tk.DISABLED)
        else:
            # 普通用户没有操作权限
            self.edit_btn.config(state=tk.DISABLED)
            self.approve_btn.config(state=tk.DISABLED)
            self.reject_btn.config(state=tk.DISABLED)
            self.delete_btn.config(state=tk.DISABLED)
    
    def create_activity(self):
        """创建新活动"""
        dialog = tk.Toplevel(self)
        dialog.title("创建新活动")
        dialog.geometry("500x400")
        dialog.transient(self)
        dialog.grab_set()
        
        ttk.Label(dialog, text="活动标题:").pack(pady=(20, 5), padx=20, anchor="w")
        title_entry = ttk.Entry(dialog, width=40)
        title_entry.pack(padx=20, fill=tk.X)
        
        ttk.Label(dialog, text="活动描述:").pack(pady=(10, 5), padx=20, anchor="w")
        desc_text = tk.Text(dialog, height=8, width=50)
        desc_text.pack(padx=20, fill=tk.X)
        
        ttk.Label(dialog, text="开始时间 (YYYY-MM-DD HH:MM):").pack(pady=(10, 5), padx=20, anchor="w")
        start_entry = ttk.Entry(dialog, width=30)
        start_entry.pack(padx=20, fill=tk.X)
        
        ttk.Label(dialog, text="结束时间 (可选):").pack(pady=(10, 5), padx=20, anchor="w")
        end_entry = ttk.Entry(dialog, width=30)
        end_entry.pack(padx=20, fill=tk.X)
        
        status_label = ttk.Label(dialog, text="", foreground="red")
        status_label.pack(pady=5)
        
        def save_activity():
            title = title_entry.get()
            description = desc_text.get("1.0", tk.END).strip()
            start_time = start_entry.get()
            end_time = end_entry.get()
            
            if not title or not start_time:
                status_label.config(text="标题和开始时间不能为空")
                return
                
            try:
                # 验证时间格式
                datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M")
                if end_time:
                    datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M")
            except ValueError:
                status_label.config(text="时间格式错误，请使用 YYYY-MM-DD HH:MM 格式")
                return
                
            # 保存到数据库
            conn = sqlite3.connect('system.db')
            cursor = conn.cursor()
            
            cursor.execute('''INSERT INTO activities 
                          (title, description, start_time, end_time, created_by)
                          VALUES (?, ?, ?, ?, ?)''',
                          (title, description, start_time, end_time or None, 
                          self.controller.current_user))
            
            conn.commit()
            conn.close()
            
            dialog.destroy()
            self.load_activities()
            self.status_bar.config(text="活动创建成功", foreground="green")
            log_action(self.controller.current_user, "CREATE_ACTIVITY")
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="保存", command=save_activity).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
    
    def edit_activity(self):
        """编辑活动"""
        if not self.selected_activity:
            return
            
        # 获取活动数据
        conn = sqlite3.connect('system.db')
        cursor = conn.cursor()
        cursor.execute("SELECT title, description, start_time, end_time, status FROM activities WHERE id=?", 
                      (self.selected_activity,))
        activity = cursor.fetchone()
        conn.close()
        
        if not activity:
            return
            
        dialog = tk.Toplevel(self)
        dialog.title("编辑活动")
        dialog.geometry("500x400")
        dialog.transient(self)
        dialog.grab_set()
        
        ttk.Label(dialog, text="活动标题:").pack(pady=(20, 5), padx=20, anchor="w")
        title_entry = ttk.Entry(dialog, width=40)
        title_entry.insert(0, activity[0])
        title_entry.pack(padx=20, fill=tk.X)
        
        ttk.Label(dialog, text="活动描述:").pack(pady=(10, 5), padx=20, anchor="w")
        desc_text = tk.Text(dialog, height=8, width=50)
        desc_text.insert("1.0", activity[1] if activity[1] else "")
        desc_text.pack(padx=20, fill=tk.X)
        
        ttk.Label(dialog, text="开始时间 (YYYY-MM-DD HH:MM):").pack(pady=(10, 5), padx=20, anchor="w")
        start_entry = ttk.Entry(dialog, width=30)
        start_entry.insert(0, activity[2])
        start_entry.pack(padx=20, fill=tk.X)
        
        ttk.Label(dialog, text="结束时间 (可选):").pack(pady=(10, 5), padx=20, anchor="w")
        end_entry = ttk.Entry(dialog, width=30)
        if activity[3]:
            end_entry.insert(0, activity[3])
        end_entry.pack(padx=20, fill=tk.X)
        
        # 状态选择（仅创作者和管理员）
        if self.controller.current_role in ("creator", "admin"):
            ttk.Label(dialog, text="状态:").pack(pady=(10, 5), padx=20, anchor="w")
            
            status_var = tk.StringVar(value=activity[4])
            status_frame = ttk.Frame(dialog)
            status_frame.pack(padx=20, fill=tk.X)
            
            ttk.Radiobutton(status_frame, text="待审核", variable=status_var, value="pending").pack(side=tk.LEFT)
            ttk.Radiobutton(status_frame, text="已通过", variable=status_var, value="approved").pack(side=tk.LEFT, padx=10)
            ttk.Radiobutton(status_frame, text="已拒绝", variable=status_var, value="rejected").pack(side=tk.LEFT)
        
        status_label = ttk.Label(dialog, text="", foreground="red")
        status_label.pack(pady=5)
        
        def save_changes():
            title = title_entry.get()
            description = desc_text.get("1.0", tk.END).strip()
            start_time = start_entry.get()
            end_time = end_entry.get()
            
            if not title or not start_time:
                status_label.config(text="标题和开始时间不能为空")
                return
                
            try:
                # 验证时间格式
                datetime.datetime.strptime(start_time, "%Y-%m-%d %H:%M")
                if end_time:
                    datetime.datetime.strptime(end_time, "%Y-%m-%d %H:%M")
            except ValueError:
                status_label.config(text="时间格式错误，请使用 YYYY-MM-DD HH:MM 格式")
                return
                
            # 更新数据库
            conn = sqlite3.connect('system.db')
            cursor = conn.cursor()
            
            if self.controller.current_role in ("creator", "admin"):
                new_status = status_var.get()
                cursor.execute('''UPDATE activities SET 
                              title=?, description=?, start_time=?, end_time=?, status=?
                              WHERE id=?''',
                              (title, description, start_time, end_time or None, new_status, 
                              self.selected_activity))
            else:
                cursor.execute('''UPDATE activities SET 
                              title=?, description=?, start_time=?, end_time=?
                              WHERE id=?''',
                              (title, description, start_time, end_time or None, 
                              self.selected_activity))
            
            conn.commit()
            conn.close()
            
            dialog.destroy()
            self.load_activities()
            self.status_bar.config(text="活动已更新", foreground="green")
            log_action(self.controller.current_user, "UPDATE_ACTIVITY", self.selected_activity)
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="保存", command=save_changes).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=10)
    
    def change_status(self, status):
        """更改活动状态"""
        if not self.selected_activity:
            return
            
        conn = sqlite3.connect('system.db')
        conn.execute("UPDATE activities SET status=? WHERE id=?", 
                   (status, self.selected_activity))
        conn.commit()
        conn.close()
        
        self.load_activities()
        self.status_bar.config(text=f"活动状态已更新: {status}", foreground="green")
        log_action(self.controller.current_user, f"CHANGE_STATUS_{status.upper()}", self.selected_activity)
    
    def delete_activity(self):
        """删除活动"""
        if not self.selected_activity or not messagebox.askyesno("确认", "确定要删除此活动吗？"):
            return
            
        conn = sqlite3.connect('system.db')
        conn.execute("DELETE FROM activities WHERE id=?", (self.selected_activity,))
        conn.commit()
        conn.close()
        
        self.load_activities()
        self.status_bar.config(text="活动已删除", foreground="green")
        log_action(self.controller.current_user, "DELETE_ACTIVITY", self.selected_activity)
    
    def logout(self):
        log_action(self.controller.current_user, "LOGOUT")
        self.controller.current_user = None
        self.controller.current_role = None
        self.controller.show_frame(LoginFrame)

# ====================== 主程序入口 ======================
if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("system.log", encoding="utf-8"),
            logging.StreamHandler()
        ]
    )
    
    app = MainApp()
    app.mainloop()
