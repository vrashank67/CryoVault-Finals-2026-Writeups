import bpy
import os
import numpy as np
from mathutils import Vector

scene = bpy.context.scene
mount = bpy.data.objects["CCTV.002"]
fixed_cameras = [bpy.data.objects[f"CCTV.{i:03d}"] for i in (1, 3, 4, 5, 6)]

# Estimate the common surveillance target from the five cameras that did not move.
a = np.zeros((3, 3), dtype=float)
b = np.zeros(3, dtype=float)
for obj in fixed_cameras:
    direction = np.array(obj.rotation_euler.to_quaternion() @ Vector((0, 0, -1)), dtype=float)
    origin = np.array(obj.location, dtype=float)
    projection = np.eye(3) - np.outer(direction, direction)
    a += projection
    b += projection @ origin
target = Vector(np.linalg.solve(a, b))

direction = (target - mount.location).normalized()
data = bpy.data.cameras.new("Reconstructed inward view")
camera = bpy.data.objects.new("Reconstructed inward view", data)
scene.collection.objects.link(camera)
camera.location = mount.location + direction * 0.32
camera.rotation_euler = direction.to_track_quat("-Z", "Y").to_euler()
data.lens = 18.0
data.clip_start = 0.03
scene.camera = camera
scene.render.engine = "BLENDER_EEVEE"
scene.render.resolution_x = 1600
scene.render.resolution_y = 900
scene.render.resolution_percentage = 100
scene.render.image_settings.file_format = "PNG"
scene.render.filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sightline_view.png")
bpy.ops.render.render(write_still=True)
print("Estimated inward aim point:", tuple(round(v, 3) for v in target))
