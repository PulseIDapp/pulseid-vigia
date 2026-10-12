#!/usr/bin/env node
// Vigía del registro de transparencia de PulseID.
//
// Comprueba, sin confiar en PulseID, que el registro de comprobantes de
// https://pulseids.com solo crece: que nadie lo ha reescrito, recortado ni
// firmado con una clave distinta desde la última vez que miraste.
//
//   node vigia-registro.mjs                 # usa ./vigia-registro.json como memoria
//   node vigia-registro.mjs --estado=ruta   # otra ruta para la memoria
//   node vigia-registro.mjs --base=https://pulseids.com
//
// Salida:  0 todo en orden · 1 no se pudo comprobar (red, servicio) · 2 ALERTA
//
// Qué hace, en orden:
//   1. Descarga la clave pública del registro. La primera vez la fija (TOFU):
//      si más adelante desaparece sin que haya una rotación publicada, alerta.
//   2. Descarga la cabecera firmada (tamaño + raíz + fecha) y comprueba su
//      firma ES256 con esa clave.
//   3. Si ya guardaste una cabecera antes: el tamaño no puede bajar, con el
//      mismo tamaño la raíz no puede cambiar, y si creció pide una prueba de
//      consistencia y la comprueba aquí (RFC 9162 §2.1.4.2).
//   4. Guarda la cabecera nueva. Las cabeceras firmadas que acumulas son tu
//      evidencia: con ellas cualquiera puede comprobar después lo que viste.
//
// No sabe nada de los comprobantes ni de las personas: el registro solo
// publica hojas cegadas. Requiere Node 20 o posterior. Sin dependencias.
// Código abierto y autocontenido: léelo antes de ejecutarlo.

import { createHash, createPublicKey, verify } from 'node:crypto'
import { readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const HEX64 = /^[0-9a-f]{64}$/
const sha256 = (...b) => createHash('sha256').update(Buffer.concat(b)).digest()
const nodo = (a, b) => sha256(Buffer.from([1]), a, b)

/** RFC 9162 §2.1.4.2. Escrito aquí aparte de PulseID a propósito. */
export function verificarConsistencia(m, n, raizM, raizN, prueba) {
  if (!(Number.isInteger(m) && Number.isInteger(n)) || m < 1 || m > n) return false
  const rm = Buffer.from(raizM, 'hex')
  const rn = Buffer.from(raizN, 'hex')
  if (m === n) return prueba.length === 0 && rm.equals(rn)
  if (!Array.isArray(prueba) || prueba.length === 0 || !prueba.every((p) => HEX64.test(p))) return false
  const ruta = (m & (m - 1)) === 0 ? [rm, ...prueba.map((p) => Buffer.from(p, 'hex'))] : prueba.map((p) => Buffer.from(p, 'hex'))
  let fn = m - 1
  let sn = n - 1
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1 }
  let fr = ruta[0]
  let sr = ruta[0]
  for (const c of ruta.slice(1)) {
    if (sn === 0) return false
    if ((fn & 1) === 1 || fn === sn) {
      fr = nodo(c, fr)
      sr = nodo(c, sr)
      if ((fn & 1) === 0) { while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1 } }
    } else {
      sr = nodo(sr, c)
    }
    fn >>= 1
    sn >>= 1
  }
  return fr.equals(rm) && sr.equals(rn) && sn === 0
}

/** Firma ES256 de la cabecera, sobre su forma canónica. */
export function firmaValida(c, jwk) {
  try {
    if (c.alg !== 'ES256' || c.v !== 1 || !HEX64.test(c.raiz) || !Number.isInteger(c.tamano)) return false
    const canon = JSON.stringify({ fecha: new Date(c.fecha).toISOString(), raiz: c.raiz, tamano: c.tamano, v: c.v })
    return verify('sha256', Buffer.from(canon), { key: createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
      Buffer.from(c.firma, 'base64url'))
  } catch {
    return false
  }
}

const huellaClave = (k) => createHash('sha256').update(`${k.x}.${k.y}`).digest('hex').slice(0, 16)

/**
 * Una pasada. No toca disco: recibe la memoria y devuelve la nueva.
 * @returns {Promise<{ codigo: 0|1|2, mensajes: string[], estado: object }>}
 */
export async function vigilar({ base = 'https://pulseids.com', estado = {}, fetch: f = globalThis.fetch } = {}) {
  const mensajes = []
  const alerta = (m) => ({ codigo: 2, mensajes: [...mensajes, `ALERTA: ${m}`], estado })
  const sinComprobar = (m) => ({ codigo: 1, mensajes: [...mensajes, `No se ha podido comprobar: ${m}`], estado })
  let jwks, cab
  try {
    const rk = await f(`${base}/api/transparencia/clave`)
    if (!rk.ok) return sinComprobar(`la clave respondió ${rk.status}`)
    jwks = await rk.json()
    const rc = await f(`${base}/api/transparencia/cabecera`)
    if (rc.status === 500) {
      const e = await rc.json().catch(() => ({}))
      if (e.error === 'registro_inconsistente' || e.error === 'registro_con_huecos') return alerta(`el propio servidor declara el registro alterado (${e.error})`)
    }
    if (!rc.ok) return sinComprobar(`la cabecera respondió ${rc.status}`)
    cab = await rc.json()
  } catch (e) {
    return sinComprobar(String(e?.message || e))
  }

  const claves = (jwks.keys || []).filter((k) => k.kty === 'EC' && k.crv === 'P-256' && k.kid)
  const fijadas = estado.claves || {}
  // Una clave fijada que desaparece sin que su kid siga publicado es un cambio
  // de clave sin transición: justo lo que una rotación honesta no hace.
  for (const [kid, huella] of Object.entries(fijadas)) {
    const actual = claves.find((k) => k.kid === kid)
    if (actual && huellaClave(actual) !== huella) return alerta(`la clave «${kid}» ha cambiado de valor`)
  }
  const usada = claves.find((k) => k.kid === cab.kid)
  if (!usada) return alerta(`la cabecera dice firmar con «${cab.kid}» y esa clave no está publicada`)
  if (Object.keys(fijadas).length && !(cab.kid in fijadas) && !claves.some((k) => k.kid in fijadas)) {
    return alerta(`ninguna de las claves que conocías sigue publicada y la cabecera firma con una nueva («${cab.kid}»)`)
  }
  if (!firmaValida(cab, usada)) return alerta('la firma de la cabecera no es válida')
  mensajes.push(`Cabecera firmada válida: ${cab.tamano} anotaciones, ${cab.fecha} (clave ${cab.kid}).`)

  const previa = estado.ultima
  if (previa) {
    if (cab.tamano < previa.tamano) return alerta(`el registro ha encogido: ${previa.tamano} → ${cab.tamano}`)
    if (cab.tamano === previa.tamano) {
      if (cab.raiz !== previa.raiz) return alerta(`mismo tamaño (${cab.tamano}) y raíz distinta: el registro se ha reescrito`)
      mensajes.push('Sin anotaciones nuevas desde la última vez.')
    } else if (previa.tamano === 0) {
      mensajes.push(`Ha empezado a crecer: ${cab.tamano} anotaciones.`)
    } else {
      let r
      try {
        const rr = await f(`${base}/api/transparencia/consistencia?de=${previa.tamano}&a=${cab.tamano}`)
        if (!rr.ok) return sinComprobar(`la prueba de consistencia respondió ${rr.status}`)
        r = await rr.json()
      } catch (e) {
        return sinComprobar(String(e?.message || e))
      }
      if (!verificarConsistencia(previa.tamano, cab.tamano, previa.raiz, cab.raiz, r.prueba || [])) {
        return alerta(`la prueba de consistencia ${previa.tamano} → ${cab.tamano} no se sostiene: lo que viste antes ya no está tal cual`)
      }
      mensajes.push(`Consistencia comprobada: ${previa.tamano} → ${cab.tamano} sin cambios en lo anterior.`)
    }
  } else {
    mensajes.push('Primera vez: se guardan la clave y la cabecera para compararlas en la siguiente.')
  }

  const claves2 = { ...fijadas }
  for (const k of claves) if (!(k.kid in claves2)) claves2[k.kid] = huellaClave(k)
  const historial = [...(estado.historial || []), { tamano: cab.tamano, raiz: cab.raiz, fecha: cab.fecha, kid: cab.kid, firma: cab.firma }].slice(-500)
  return { codigo: 0, mensajes, estado: { claves: claves2, ultima: { tamano: cab.tamano, raiz: cab.raiz, fecha: cab.fecha, kid: cab.kid, firma: cab.firma }, historial } }
}

// ── Línea de órdenes ─────────────────────────────────────────────────────────
if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  const arg = (n, def) => (process.argv.find((a) => a.startsWith(`--${n}=`)) || '').split('=').slice(1).join('=') || def
  const ruta = arg('estado', 'vigia-registro.json')
  const base = arg('base', 'https://pulseids.com').replace(/\/$/, '')
  let estado = {}
  if (existsSync(ruta)) {
    try { estado = JSON.parse(readFileSync(ruta, 'utf8')) } catch { console.error(`No se puede leer ${ruta}: no lo sobrescribo.`); process.exit(1) }
  }
  const r = await vigilar({ base, estado })
  for (const m of r.mensajes) console.log(m)
  // Solo se guarda lo comprobado. Ante una alerta, la memoria se queda como
  // estaba: es la prueba de lo que viste antes.
  if (r.codigo === 0) { writeFileSync(`${ruta}.tmp`, JSON.stringify(r.estado, null, 2)); renameSync(`${ruta}.tmp`, ruta) }
  process.exit(r.codigo)
}
