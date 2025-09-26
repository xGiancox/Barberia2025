from PIL import Image
import os

# Redimensionar logo si es muy grande
def resize_logo(input_path, output_path, max_size=(300, 300)):
    try:
        with Image.open(input_path) as img:
            img.thumbnail(max_size, Image.Resampling.LANCZOS)
            img.save(output_path, optimize=True, quality=85)
        print(f"✅ Logo optimizado: {output_path}")
    except Exception as e:
        print(f"❌ Error: {e}")

# Ejecutar si el archivo existe
if os.path.exists('static/images/logo.jpg'):
    resize_logo('static/images/logo.jpg', 'static/images/logo_optimized.jpg')
else:
    print("⚠️  Sube primero tu logo como 'static/images/logo.jpg'")