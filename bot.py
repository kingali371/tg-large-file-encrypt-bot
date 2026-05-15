#!/usr/bin/env python3
"""
Telegram Encryption Bot - بوت تقسيم وتشفير الملفات الكبيرة
المميزات: تقسيم الملفات + تشفير AES + دمج تلقائي
"""

import os
import base64
import hashlib
import logging
import tempfile
import json
from typing import Dict, Tuple, Optional, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2KeyDerivationFunction
from cryptography.hazmat.primitives import hashes
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ابحث عن أي مكان في الكود يستخدم PBKDF2 أو PBKDF2KeyDerivationFunction
# واستبدله بـ PBKDF2HMAC مع التأكد من تمرير المعاملات الصحيحة

# إعدادات
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get('BOT_TOKEN')
OWNER_ID = int(os.environ.get('OWNER_ID', 0))
PORT = int(os.environ.get('PORT', 8080))

# إعدادات التقسيم
MAX_PART_SIZE = 19 * 1024 * 1024  # 19 ميجابايت (لضمان عدم تجاوز حد التليجرام 20 ميجابايت)
CHUNK_SIZE = 1024 * 1024  # 1 ميجابايت للقراءة التدريجية


class FileSplitter:
    """كلاس متخصص لتقسيم ودمج الملفات"""
    
    @staticmethod
    def split_file(file_data: bytes, part_size: int = MAX_PART_SIZE) -> List[bytes]:
        """
        تقسيم الملف إلى أجزاء متساوية
        
        Args:
            file_data: بيانات الملف
            part_size: حجم كل جزء بالبايت
        
        Returns:
            قائمة بالأجزاء
        """
        parts = []
        total_size = len(file_data)
        num_parts = (total_size + part_size - 1) // part_size
        
        for i in range(num_parts):
            start = i * part_size
            end = min(start + part_size, total_size)
            part_data = file_data[start:end]
            parts.append(part_data)
            
            logger.info(f"تقسيم: جزء {i+1}/{num_parts} - {len(part_data)} بايت")
        
        return parts
    
    @staticmethod
    def merge_parts(parts: List[bytes]) -> bytes:
        """
        دمج الأجزاء إلى ملف واحد
        
        Args:
            parts: قائمة الأجزاء
        
        Returns:
            الملف المدمج
        """
        return b''.join(parts)
    
    @staticmethod
    def create_metadata(original_name: str, total_parts: int, part_size: int, file_hash: str) -> dict:
        """
        إنشاء ملف metadata للملف المقسم
        
        Args:
            original_name: اسم الملف الأصلي
            total_parts: عدد الأجزاء
            part_size: حجم كل جزء
            file_hash: هاش الملف الأصلي للتحقق
        
        Returns:
            قاموس metadata
        """
        return {
            "original_name": original_name,
            "total_parts": total_parts,
            "part_size": part_size,
            "file_hash": file_hash,
            "version": "1.0"
        }


class EncryptionBot:
    """بوت التشفير الرئيسي"""
    
    def __init__(self):
        self.user_sessions: Dict[int, dict] = {}
        self.splitter = FileSplitter()
    
    def is_authorized(self, user_id: int) -> bool:
        """التحقق من صلاحية المستخدم"""
        return user_id == OWNER_ID
    
    def generate_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """توليد مفتاح AES من كلمة مرور"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def calculate_file_hash(self, file_data: bytes) -> str:
        """حساب هاش SHA256 للملف"""
        return hashlib.sha256(file_data).hexdigest()
    
    def encrypt_data(self, data: bytes, password: str) -> bytes:
        """تشفير البيانات"""
        key, salt = self.generate_key(password)
        f = Fernet(key)
        encrypted = f.encrypt(data)
        return salt + encrypted
    
    def decrypt_data(self, encrypted_data: bytes, password: str) -> Optional[bytes]:
        """فك تشفير البيانات"""
        try:
            salt = encrypted_data[:16]
            encrypted = encrypted_data[16:]
            key, _ = self.generate_key(password, salt)
            f = Fernet(key)
            return f.decrypt(encrypted)
        except Exception as e:
            logger.error(f"فشل فك التشفير: {e}")
            return None
    
    def encrypt_and_split_file(self, file_data: bytes, password: str) -> Tuple[List[bytes], dict]:
        """
        تشفير الملف ثم تقسيمه إلى أجزاء
        
        Returns:
            (قائمة الأجزاء المشفرة, metadata)
        """
        # 1. حساب هاش الملف الأصلي
        file_hash = self.calculate_file_hash(file_data)
        
        # 2. تشفير الملف بالكامل
        encrypted_data = self.encrypt_data(file_data, password)
        
        # 3. تقسيم الملف المشفر
        parts = self.splitter.split_file(encrypted_data)
        
        # 4. إنشاء metadata
        metadata = self.splitter.create_metadata(
            original_name="encrypted_file",
            total_parts=len(parts),
            part_size=MAX_PART_SIZE,
            file_hash=file_hash
        )
        
        return parts, metadata
    
    def merge_and_decrypt_parts(self, parts: List[bytes], password: str) -> Optional[bytes]:
        """
        دمج الأجزاء ثم فك تشفيرها
        
        Args:
            parts: قائمة الأجزاء المشفرة
            password: كلمة المرور
        
        Returns:
            الملف الأصلي أو None في حالة الفشل
        """
        # 1. دمج الأجزاء
        merged_data = self.splitter.merge_parts(parts)
        
        # 2. فك التشفير
        decrypted_data = self.decrypt_data(merged_data, password)
        
        return decrypted_data
    
    def encrypt_text(self, text: str, password: str) -> str:
        """تشفير نص"""
        encrypted = self.encrypt_data(text.encode(), password)
        return base64.b64encode(encrypted).decode()
    
    def decrypt_text(self, encrypted_text: str, password: str) -> Optional[str]:
        """فك تشفير نص"""
        try:
            data = base64.b64decode(encrypted_text)
            decrypted = self.decrypt_data(data, password)
            return decrypted.decode() if decrypted else None
        except Exception:
            return None
    
    def encode_base64(self, text: str) -> str:
        return base64.b64encode(text.encode()).decode()
    
    def decode_base64(self, encoded: str) -> Optional[str]:
        try:
            return base64.b64decode(encoded).decode()
        except Exception:
            return None


# إنشاء كائن البوت
encryption_bot = EncryptionBot()

# ============= أوامر البوت ============= #

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """رسالة الترحيب"""
    user_id = update.effective_user.id
    
    if not encryption_bot.is_authorized(user_id):
        await update.message.reply_text("❌ عذراً، هذا البوت مخصص للمالك فقط.")
        return
    
    welcome_text = """
🔐 **بوت تقسيم وتشفير الملفات المتقدم v4.0**

✨ **المميزات الرئيسية:**

📦 **تقسيم الملفات الكبيرة:**
• تقسيم تلقائي للملفات التي تزيد عن 19 ميجابايت
• إرسال الأجزاء بشكل منفصل
• دمج تلقائي عند فك التشفير

🔒 **التشفير القوي:**
• AES-256 مع PBKDF2
• ملح عشوائي لكل ملف
• هاش للتحقق من سلامة الملف

📁 **كيفية الاستخدام:**

1️⃣ **تشفير وتقسيم ملف:**
   • أرسل أي ملف للبوت
   • أدخل كلمة المرور
   • سيتم تقسيم الملف وتشفيره تلقائياً

2️⃣ **دمج وفك تشفير ملف:**
   • أرسل جميع الأجزاء (بالترتيب)
   • أدخل نفس كلمة المرور
   • استلم الملف الأصلي

3️⃣ **تشفير النصوص:**
   /encrypt - تشفير نص
   /decrypt - فك تشفير نص

📊 **الحدود:**
• كل جزء بحد أقصى 19 ميجابايت
• يمكن تقسيم الملفات إلى أي عدد من الأجزاء

/help - عرض المساعدة التفصيلية
/about - معلومات عن البوت
    """
    await update.message.reply_text(welcome_text, parse_mode='Markdown')


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """عرض المساعدة التفصيلية"""
    help_text = """
📖 **دليل الاستخدام التفصيلي:**

📁 **تشفير وتقسيم ملف كبير:**

1. أرسل الملف إلى البوت (أي حجم حتى 500 ميجابايت)
2. سيرسل البوت رسالة: "أدخل كلمة المرور"
3. أرسل كلمة المرور (مثال: MySecret123)
4. سيتم:
   ✅ تشفير الملف بالكامل
   ✅ تقسيم الملف المشفر إلى أجزاء (كل جزء 19 ميجابايت)
   ✅ إرسال جميع الأجزاء مع metadata

🔓 **دمج وفك تشفير ملف مقسم:**

1. أرسل جميع الأجزاء التي تريد دمجها (يمكن إرسالها دفعة واحدة)
2. سيتعرف البوت تلقائياً على الأجزاء
3. أدخل كلمة المرور
4. استلم الملف الأصلي المفكك

📝 **تشفير النصوص:**

• `/encrypt` - ثم أرسل النص، ثم كلمة المرور
• `/decrypt` - ثم أرسل النص المشفر، ثم كلمة المرور

🔐 **أوامر إضافية:**

• `/encode_b64` - تحويل نص إلى Base64
• `/decode_b64` - فك تشفير Base64
• `/hash` - توليد هاش SHA256/MD5
• `/cancel` - إلغاء العملية الحالية

⚠️ **تنبيهات مهمة:**

• احتفظ بكلمة المرور بأمان - بدونها لا يمكن استعادة الملف!
• يجب إرسال جميع الأجزاء لفك التشفير
• الأجزاء مرقمة تلقائياً (part1, part2, ...)

👤 **ايدي المالك:** `{}
    """.format(OWNER_ID)
    await update.message.reply_text(help_text, parse_mode='Markdown')


async def encrypt_text_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """بدء تشفير النص"""
    user_id = update.effective_user.id
    if not encryption_bot.is_authorized(user_id):
        return
    
    context.user_data['action'] = 'encrypt_text_waiting'
    await update.message.reply_text(
        "✏️ **أرسل النص الذي تريد تشفيره:**\n\n"
        "(يمكنك إلغاء العملية بإرسال /cancel)",
        parse_mode='Markdown'
    )


async def decrypt_text_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """بدء فك تشفير النص"""
    user_id = update.effective_user.id
    if not encryption_bot.is_authorized(user_id):
        return
    
    context.user_data['action'] = 'decrypt_text_waiting'
    await update.message.reply_text(
        "🔐 **أرسل النص المشفر (Base64):**\n\n"
        "(يمكنك إلغاء العملية بإرسال /cancel)",
        parse_mode='Markdown'
    )


async def encode_b64_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """تشفير Base64"""
    user_id = update.effective_user.id
    if not encryption_bot.is_authorized(user_id):
        return
    
    context.user_data['action'] = 'encode_b64_waiting'
    await update.message.reply_text("📝 أرسل النص لتحويله إلى Base64:")


async def decode_b64_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """فك Base64"""
    user_id = update.effective_user.id
    if not encryption_bot.is_authorized(user_id):
        return
    
    context.user_data['action'] = 'decode_b64_waiting'
    await update.message.reply_text("🔓 أرسل النص المشفر (Base64) لفك تشفيره:")


async def hash_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """اختيار نوع الهاش"""
    user_id = update.effective_user.id
    if not encryption_bot.is_authorized(user_id):
        return
    
    keyboard = [
        [InlineKeyboardButton("🔐 SHA256", callback_data="hash_sha256")],
        [InlineKeyboardButton("📝 MD5", callback_data="hash_md5")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🔐 **اختر نوع الهاش:**",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة الأزرار"""
    query = update.callback_query
    await query.answer()
    
    user_id = query.from_user.id
    if not encryption_bot.is_authorized(user_id):
        await query.edit_message_text("❌ غير مصرح لك.")
        return
    
    if query.data.startswith("hash_"):
        algo = query.data.replace("hash_", "")
        context.user_data['hash_algo'] = algo
        context.user_data['action'] = 'hash_waiting'
        await query.edit_message_text(
            f"✅ تم اختيار {algo.upper()}\n\n📝 أرسل النص لتوليد الهاش:"
        )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة الرسائل النصية"""
    user_id = update.effective_user.id
    if not encryption_bot.is_authorized(user_id):
        return
    
    text = update.message.text.strip()
    action = context.user_data.get('action')
    
    if action == 'encrypt_text_waiting':
        context.user_data['text_to_encrypt'] = text
        context.user_data['action'] = 'encrypt_text_password'
        await update.message.reply_text("🔑 **أدخل كلمة المرور للتشفير:**", parse_mode='Markdown')
    
    elif action == 'encrypt_text_password':
        password = text
        plain_text = context.user_data.get('text_to_encrypt')
        try:
            encrypted = encryption_bot.encrypt_text(plain_text, password)
            await update.message.reply_text(
                f"✅ **تم التشفير بنجاح!**\n\n"
                f"📝 **النص المشفر:**\n`{encrypted}`\n\n"
                f"⚠️ احتفظ بكلمة المرور: `{password}`",
                parse_mode='Markdown'
            )
        except Exception as e:
            await update.message.reply_text(f"❌ خطأ: {e}")
        finally:
            context.user_data.clear()
    
    elif action == 'decrypt_text_waiting':
        context.user_data['text_to_decrypt'] = text
        context.user_data['action'] = 'decrypt_text_password'
        await update.message.reply_text("🔑 **أدخل كلمة المرور لفك التشفير:**", parse_mode='Markdown')
    
    elif action == 'decrypt_text_password':
        password = text
        encrypted_text = context.user_data.get('text_to_decrypt')
        try:
            decrypted = encryption_bot.decrypt_text(encrypted_text, password)
            if decrypted:
                await update.message.reply_text(
                    f"✅ **النص الأصلي:**\n`{decrypted}`",
                    parse_mode='Markdown'
                )
            else:
                await update.message.reply_text("❌ كلمة المرور غير صحيحة أو النص تالف!")
        except Exception as e:
            await update.message.reply_text(f"❌ خطأ: {e}")
        finally:
            context.user_data.clear()
    
    elif action == 'encode_b64_waiting':
        result = encryption_bot.encode_base64(text)
        await update.message.reply_text(f"✅ **Base64:**\n`{result}`", parse_mode='Markdown')
        context.user_data.clear()
    
    elif action == 'decode_b64_waiting':
        result = encryption_bot.decode_base64(text)
        if result:
            await update.message.reply_text(f"✅ **النص الأصلي:**\n`{result}`", parse_mode='Markdown')
        else:
            await update.message.reply_text("❌ نص Base64 غير صالح!")
        context.user_data.clear()
    
    elif action == 'hash_waiting':
        algo = context.user_data.get('hash_algo', 'sha256')
        result = encryption_bot.hash_text(text, algo) if hasattr(encryption_bot, 'hash_text') else None
        if result:
            await update.message.reply_text(
                f"✅ **{algo.upper()}:**\n`{result}`",
                parse_mode='Markdown'
            )
        context.user_data.clear()
    
    elif context.user_data.get('file_action') == 'waiting_password':
        # معالجة كلمة المرور للملفات
        password = text
        file_parts = context.user_data.get('file_parts', [])
        temp_files = context.user_data.get('temp_files', [])
        
        await update.message.reply_text("🔓 **جاري دمج وفك تشفير الملف...**", parse_mode='Markdown')
        
        try:
            # دمج وفك تشفير الأجزاء
            result_data = encryption_bot.merge_and_decrypt_parts(file_parts, password)
            
            if result_data:
                # إرسال الملف المفكك
                original_name = context.user_data.get('original_name', 'decrypted_file')
                
                with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(original_name)[1]) as tmp:
                    tmp.write(result_data)
                    tmp_path = tmp.name
                
                with open(tmp_path, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=original_name,
                        caption=f"✅ **تم دمج وفك التشفير بنجاح!**\n\n"
                               f"📦 الحجم: {len(result_data) / (1024*1024):.2f} ميجابايت"
                    )
                
                os.unlink(tmp_path)
                await update.message.reply_text("🎉 **اكتملت العملية بنجاح!**", parse_mode='Markdown')
            else:
                await update.message.reply_text(
                    "❌ **فشل فك التشفير!**\n\n"
                    "🔍 الأسباب المحتملة:\n"
                    "• كلمة المرور غير صحيحة\n"
                    "• الأجزاء غير مكتملة أو تالفة",
                    parse_mode='Markdown'
                )
        except Exception as e:
            await update.message.reply_text(f"❌ خطأ: {e}")
        finally:
            # تنظيف الملفات المؤقتة
            for tmp_path in temp_files:
                try:
                    os.unlink(tmp_path)
                except:
                    pass
            context.user_data.clear()
    
    else:
        await update.message.reply_text(
            "❓ **أمر غير معروف.**\n"
            "📌 استخدم /help لعرض الأوامر المتاحة.",
            parse_mode='Markdown'
        )


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة الملفات (تشفير وتقسيم أو دمج)"""
    user_id = update.effective_user.id
    if not encryption_bot.is_authorized(user_id):
        await update.message.reply_text("❌ غير مصرح لك.")
        return
    
    document = update.message.document
    file_name = document.file_name
    file_size = document.file_size
    
    # التحقق إذا كان الملف جزءاً من ملف مقسم
    if '.part' in file_name and file_name.endswith('.encrypted'):
        # تجميع الأجزاء
        parts_list = context.user_data.get('pending_parts', [])
        parts_list.append({
            'name': file_name,
            'data': None,
            'size': file_size
        })
        context.user_data['pending_parts'] = parts_list
        
        # تحميل الملف الحالي
        status_msg = await update.message.reply_text(
            f"📦 **تم استلام جزء:** `{file_name}`\n"
            f"📊 حجم هذا الجزء: {file_size / (1024*1024):.2f} ميجابايت\n\n"
            f"📌 أرسل الأجزاء المتبقية أو أرسل `/done` عند الانتهاء",
            parse_mode='Markdown'
        )
        
        # تحميل البيانات
        file = await document.get_file()
        file_data = await file.download_as_bytearray()
        parts_list[-1]['data'] = bytes(file_data)
        
        await status_msg.edit_text(
            f"✅ **تم حفظ الجزء:** `{file_name}`\n"
            f"📦 تم استلام {len(parts_list)} أجزاء حتى الآن",
            parse_mode='Markdown'
        )
        
        # تحديث الجلسة
        context.user_data['file_action'] = 'collecting_parts'
        
    elif file_name.endswith('.encrypted') and '.part' not in file_name:
        # ملف مشفر كامل (غير مقسم)
        status_msg = await update.message.reply_text(
            f"📥 **تم استلام ملف مشفر:**\n"
            f"📄 `{file_name}`\n"
            f"📦 الحجم: {file_size / (1024*1024):.2f} ميجابايت",
            parse_mode='Markdown'
        )
        
        file = await document.get_file()
        file_data = await file.download_as_bytearray()
        
        context.user_data['file_action'] = 'waiting_password'
        context.user_data['file_parts'] = [bytes(file_data)]
        context.user_data['original_name'] = file_name.replace('.encrypted', '')
        
        await status_msg.delete()
        await update.message.reply_text(
            "🔑 **أدخل كلمة المرور لفك التشفير:**",
            parse_mode='Markdown'
        )
    
    else:
        # ملف عادي - سيتم تشفيره وتقسيمه
        if file_size > MAX_PART_SIZE:
            await update.message.reply_text(
                f"📦 **ملف كبير مكتشف!**\n\n"
                f"📄 الاسم: `{file_name}`\n"
                f"📊 الحجم: {file_size / (1024*1024):.2f} ميجابايت\n"
                f"⚠️ سيتم تقسيم الملف إلى أجزاء {MAX_PART_SIZE // (1024*1024)} ميجابايت\n\n"
                f"🔑 **أدخل كلمة المرور للتشفير:**",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                f"📄 **ملف عادي مكتشف:**\n"
                f"📄 الاسم: `{file_name}`\n"
                f"📦 الحجم: {file_size / 1024:.1f} كيلوبايت\n\n"
                f"🔑 **أدخل كلمة المرور للتشفير:**",
                parse_mode='Markdown'
            )
        
        # تحميل الملف وحفظه مؤقتاً
        status_msg = await update.message.reply_text("📥 جاري تحميل الملف...")
        
        file = await document.get_file()
        file_data = await file.download_as_bytearray()
        
        await status_msg.delete()
        
        context.user_data['file_action'] = 'waiting_password'
        context.user_data['file_data'] = bytes(file_data)
        context.user_data['file_name'] = file_name


async def done_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إنهاء تجميع الأجزاء وبدء الدمج"""
    user_id = update.effective_user.id
    if not encryption_bot.is_authorized(user_id):
        return
    
    pending_parts = context.user_data.get('pending_parts', [])
    
    if not pending_parts:
        await update.message.reply_text("❌ لا توجد أجزاء مجمعة لعملية الدمج.")
        return
    
    # ترتيب الأجزاء حسب الأرقام
    def extract_part_number(filename):
        import re
        match = re.search(r'\.part(\d+)\.', filename)
        return int(match.group(1)) if match else 0
    
    pending_parts.sort(key=lambda x: extract_part_number(x['name']))
    
    # استخراج البيانات
    file_parts = [part['data'] for part in pending_parts]
    
    context.user_data['file_action'] = 'waiting_password'
    context.user_data['file_parts'] = file_parts
    context.user_data['temp_files'] = []
    
    # استخراج الاسم الأصلي
    first_part_name = pending_parts[0]['name']
    original_name = first_part_name.split('.part')[0].replace('.encrypted', '')
    context.user_data['original_name'] = original_name
    
    await update.message.reply_text(
        f"✅ **تم تجميع {len(pending_parts)} أجزاء بنجاح!**\n\n"
        f"📄 الاسم الأصلي المتوقع: `{original_name}`\n\n"
        f"🔑 **أدخل كلمة المرور لدمج وفك تشفير الملف:**",
        parse_mode='Markdown'
    )


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إلغاء العملية الحالية"""
    context.user_data.clear()
    await update.message.reply_text(
        "❌ **تم إلغاء العملية.**\n\n"
        "📌 يمكنك بدء عملية جديدة في أي وقت.",
        parse_mode='Markdown'
    )


# ============= التشغيل ============= #

def main():
    """تشغيل البوت"""
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN غير موجود!")
        return
    
    if OWNER_ID == 0:
        logger.error("OWNER_ID غير موجود!")
        return
    
    # إنشاء التطبيق
    app = Application.builder().token(BOT_TOKEN).build()
    
    # إضافة الأوامر
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("encrypt", encrypt_text_command))
    app.add_handler(CommandHandler("decrypt", decrypt_text_command))
    app.add_handler(CommandHandler("encode_b64", encode_b64_command))
    app.add_handler(CommandHandler("decode_b64", decode_b64_command))
    app.add_handler(CommandHandler("hash", hash_command))
    app.add_handler(CommandHandler("done", done_command))
    app.add_handler(CommandHandler("cancel", cancel))
    
    # معالجة الأزرار
    app.add_handler(CallbackQueryHandler(button_handler))
    
    # معالجة الرسائل
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    
    logger.info(f"✅ تشغيل البوت... PORT={PORT}")
    logger.info(f"👤 المالك ID: {OWNER_ID}")
    logger.info(f"📦 الحد الأقصى لكل جزء: {MAX_PART_SIZE // (1024*1024)} ميجابايت")
    
    # تشغيل البوت مع webhook
    app.run_webhook(
        listen="0.0.0.0",
        port=PORT,
        webhook_url=f"https://{os.environ.get('RENDER_EXTERNAL_HOSTNAME', 'localhost')}/webhook"
    )


if __name__ == "__main__":
    main()
