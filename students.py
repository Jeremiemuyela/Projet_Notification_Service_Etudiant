"""
Gestion des étudiants avec leurs facultés et promotions
"""
import json
import os
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict
from db import get_conn

STUDENTS_FILE = "students.json"

# Définition des facultés et leurs promotions disponibles
FACULTIES = {
    "Informatique": ["L1", "L2", "L3", "L4", "M1", "M2"],
    "Ecole Superieur d'Architecture et Urbanisme": ["Prepa", "L1", "L2", "L3", "M1", "M2"],
    "Droit": ["L1", "L2", "L3", "M1", "M2"],
    "SAE": ["L1", "L2", "L3", "M1", "M2"],
    "Science Technologique": ["Prepa", "L1", "L2", "L3", "M1", "M2"],
    "SIC": ["L1", "L2", "L3", "M1", "M2"],
    "Medecine": ["L1", "L2", "L3", "M1", "M2", "D1", "D2", "D3"]  # Ajout des années de médecine
}

ALL_PROMOTIONS = set()
for promotions in FACULTIES.values():
    ALL_PROMOTIONS.update(promotions)


@dataclass
class Student:
    """Représente un étudiant."""
    id: str
    nom: str
    email: str
    telephone: Optional[str] = None
    langue: str = "fr"
    faculté: str = ""
    promotion: str = ""
    canal_prefere: str = "email"
    actif: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit l'étudiant en dictionnaire."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Student':
        """Crée un étudiant depuis un dictionnaire."""
        return cls(**data)


class StudentsManager:
    """Gestionnaire des étudiants."""
    
    def __init__(self):
        self._students: Dict[str, Student] = {}
        self._load_students()
    
    def _load_students(self):
        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("SELECT id, nom, email, telephone, langue, faculte, promotion, canal_prefere, actif FROM students")
            rows = cur.fetchall()
            if not rows:
                self._create_sample_students()
            else:
                for row in rows:
                    s = Student(
                        id=row[0],
                        nom=row[1],
                        email=row[2],
                        telephone=row[3],
                        langue=row[4] or "fr",
                        faculté=row[5] or "",
                        promotion=row[6] or "",
                        canal_prefere=row[7] or "email",
                        actif=bool(row[8]),
                    )
                    self._students[s.id] = s
            conn.close()
        except Exception as e:
            print(f"[STUDENTS] Erreur lors du chargement: {e}")
            self._create_sample_students()
    
    def _save_students(self):
        conn = get_conn()
        cur = conn.cursor()
        for student_id, student in self._students.items():
            cur.execute(
                "INSERT INTO students(id, nom, email, telephone, langue, faculte, promotion, canal_prefere, actif) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET nom=excluded.nom, email=excluded.email, telephone=excluded.telephone, langue=excluded.langue, faculte=excluded.faculte, promotion=excluded.promotion, canal_prefere=excluded.canal_prefere, actif=excluded.actif",
                (
                    student.id,
                    student.nom,
                    student.email,
                    student.telephone,
                    student.langue,
                    student.faculté,
                    student.promotion,
                    student.canal_prefere,
                    1 if student.actif else 0,
                ),
            )
        conn.commit()
        conn.close()
    
    def _create_sample_students(self):
        """Crée quelques étudiants d'exemple pour le démarrage."""
        sample_students = [
            Student("etudiant1", "Jean Dupont", "jean.dupont@univ.fr", "+33123456789", "fr", "Informatique", "L1"),
            Student("etudiant2", "Marie Martin", "marie.martin@univ.fr", "+33987654321", "fr", "Informatique", "L2"),
            Student("etudiant3", "Pierre Durand", "pierre.durand@univ.fr", None, "en", "Droit", "M1"),
            Student("etudiant4", "Sophie Bernard", "sophie.bernard@univ.fr", "+33555666777", "fr", "SAE", "L3"),
        ]
        for student in sample_students:
            self._students[student.id] = student
        self._save_students()
        print(f"[STUDENTS] {len(sample_students)} étudiants d'exemple créés")
    
    def get_all_students(self) -> List[Student]:
        """Récupère tous les étudiants."""
        return list(self._students.values())
    
    def get_student(self, student_id: str) -> Optional[Student]:
        """Récupère un étudiant par son ID."""
        return self._students.get(student_id)
    
    def add_student(self, student: Student):
        """Ajoute un étudiant."""
        self._students[student.id] = student
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO students(id, nom, email, telephone, langue, faculte, promotion, canal_prefere, actif) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                student.id,
                student.nom,
                student.email,
                student.telephone,
                student.langue,
                student.faculté,
                student.promotion,
                student.canal_prefere,
                1 if student.actif else 0,
            ),
        )
        conn.commit()
        conn.close()
    
    def update_student(self, student_id: str, **kwargs):
        """Met à jour un étudiant."""
        if student_id not in self._students:
            raise ValueError(f"Étudiant {student_id} non trouvé")
        
        student = self._students[student_id]
        for key, value in kwargs.items():
            if hasattr(student, key):
                setattr(student, key, value)
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE students SET nom=?, email=?, telephone=?, langue=?, faculte=?, promotion=?, canal_prefere=?, actif=? WHERE id=?",
            (
                student.nom,
                student.email,
                student.telephone,
                student.langue,
                student.faculté,
                student.promotion,
                student.canal_prefere,
                1 if student.actif else 0,
                student.id,
            ),
        )
        conn.commit()
        conn.close()
    
    def delete_student(self, student_id: str):
        """Supprime un étudiant."""
        if student_id in self._students:
            del self._students[student_id]
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("DELETE FROM students WHERE id=?", (student_id,))
            conn.commit()
            conn.close()
    
    def filter_students(
        self,
        facultés: Optional[List[str]] = None,
        promotions: Optional[List[str]] = None,
        actif_only: bool = True
    ) -> List[Student]:
        """
        Filtre les étudiants selon les critères.
        
        Args:
            facultés: Liste des facultés à inclure (None = toutes)
            promotions: Liste des promotions à inclure (None = toutes)
            actif_only: Ne retourner que les étudiants actifs
        
        Returns:
            Liste des étudiants correspondant aux critères
        """
        filtered = []
        
        for student in self._students.values():
            # Filtrer par statut actif
            if actif_only and not student.actif:
                continue
            
            # Filtrer par faculté
            if facultés and student.faculté not in facultés:
                continue
            
            # Filtrer par promotion
            if promotions and student.promotion not in promotions:
                continue
            
            filtered.append(student)
        
        return filtered
    
    def get_faculties(self) -> List[str]:
        """Retourne la liste des facultés."""
        return list(FACULTIES.keys())
    
    def get_promotions_for_faculty(self, faculty: str) -> List[str]:
        """Retourne les promotions disponibles pour une faculté."""
        return FACULTIES.get(faculty, [])
    
    def get_statistics(self) -> Dict[str, Any]:
        """Retourne des statistiques sur les étudiants."""
        stats = {
            "total": len(self._students),
            "actifs": sum(1 for s in self._students.values() if s.actif),
            "par_faculté": {},
            "par_promotion": {}
        }
        
        for student in self._students.values():
            # Par faculté
            if student.faculté:
                stats["par_faculté"][student.faculté] = stats["par_faculté"].get(student.faculté, 0) + 1
            
            # Par promotion
            if student.promotion:
                stats["par_promotion"][student.promotion] = stats["par_promotion"].get(student.promotion, 0) + 1
        
        return stats


# Instance globale
students_manager = StudentsManager()

